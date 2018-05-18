#
# Copyright (C) 2014-2015  UAVCAN Development Team  <uavcan.org>
#
# This software is distributed under the terms of the MIT License.
#
# Author: Ben Dyer <ben_dyer@mac.com>
#         Pavel Kirienko <pavel.kirienko@zubax.com>
#

from __future__ import division, absolute_import, print_function, unicode_literals

import threading
import time
from logging import getLogger
from typing import NamedTuple, Optional

import uavcan
from uavcan import UAVCANException


logger = getLogger(__name__)


def _unique_id_to_string(uid):
    return ' '.join(['%02X' % x for x in uid]) if uid else None


class CentralizedServer(object):
    QUERY_TIMEOUT = uavcan.protocol.dynamic_node_id.Allocation().FOLLOWUP_TIMEOUT_MS / 1000  # @UndefinedVariable
    DEFAULT_NODE_ID_RANGE = 1, 125
    DATABASE_STORAGE_MEMORY = ':memory:'

    class PruningAllocationTable:
        """
        Assigns a CAN node ID with a hardware UUID. If a node disappears, it will be removed from the table after some
        timeout period
        """
        NodeInfo = NamedTuple('NodeInfo', [('unique_id', Optional[bytes]), ('last_seen', int)])

        def __init__(self, node: uavcan.node.Node, prune_age: float = 15):
            self.node = node  # type: uavcan.node.Node
            self.prune_age = prune_age  # type: float

            self.lock = threading.Lock()
            self.ids = {}  # type: Mapping[int, PruningAllocationTable.NodeInfo]

            self.handler = self.node.add_handler(uavcan.protocol.NodeStatus, self.node_status_callback)

        def node_status_callback(self, event: uavcan.node.TransferEvent):
            self.update_timestamp(event.transfer.source_node_id)
            self.prune()

        def update_timestamp(self, node_id):
            with self.lock:
                if node_id in self.ids:
                    self.ids[node_id] = CentralizedServer.PruningAllocationTable.NodeInfo(
                        unique_id=self.ids[node_id].unique_id, last_seen=time.monotonic())

        def close(self):
            self.handler.try_remove()

        def set(self, unique_id, node_id):
            self.prune()
            with self.lock:
                if unique_id is not None and unique_id == bytes([0] * len(unique_id)):
                    unique_id = None
                self.ids[node_id] = CentralizedServer.PruningAllocationTable.NodeInfo(
                    unique_id=unique_id, last_seen=time.monotonic())

        def get_node_id(self, unique_id):
            self.prune()
            with self.lock:
                for node_id, node_info in self.ids.items():
                    if node_info.unique_id == unique_id:
                        return node_id
            return None

        def get_unique_id(self, node_id):
            self.prune()
            with self.lock:
                if node_id in self.ids:
                    return self.ids[node_id].unique_id
            return None

        def is_known_node_id(self, node_id):
            return node_id in self.ids

        def prune(self):
            with self.lock:
                old_node_ids = set()

                for node_id, node_info in self.ids.items():
                    if node_id != self.node.node_id and time.monotonic() - node_info.last_seen > self.prune_age:
                        old_node_ids.add(node_id)

                for node_id in old_node_ids:
                    del self.ids[node_id]

    def __init__(self, node, node_monitor, dynamic_node_id_range=None):
        """
        :param node: Node instance.

        :param node_monitor: Instance of NodeMonitor.

        :param database_storage: Path to the file where the instance will keep the allocation table.
                                 If not provided, the allocation table will be kept in memory.

        :param dynamic_node_id_range: Range of node ID available for dynamic allocation; defaults to [1, 125].
        """
        if node.is_anonymous:
            raise UAVCANException('Dynamic node ID server cannot be launched on an anonymous node')

        self._node_monitor = node_monitor

        self._allocation_table = CentralizedServer.PruningAllocationTable(node)
        self._query = bytes()
        self._query_timestamp = 0
        self._node_monitor_event_handle = node_monitor.add_update_handler(self._handle_monitor_event)

        self._dynamic_node_id_range = dynamic_node_id_range or CentralizedServer.DEFAULT_NODE_ID_RANGE
        self._handle = node.add_handler(uavcan.protocol.dynamic_node_id.Allocation,  # @UndefinedVariable
                                        self._on_allocation_message)

        self._allocation_table.set(node.node_info.hardware_version.unique_id.to_bytes(), node.node_id)

        # Initializing the table
        for entry in node_monitor.find_all(lambda _: True):
            unique_id = entry.info.hardware_version.unique_id.to_bytes() if entry.info else None
            self._allocation_table.set(unique_id, entry.node_id)

    def get_allocation_table(self):
        return self._allocation_table.get_entries()

    def _handle_monitor_event(self, event):
        unique_id = event.entry.info.hardware_version.unique_id.to_bytes() if event.entry.info else None
        self._allocation_table.set(unique_id, event.entry.node_id)

    def close(self):
        """Stops the instance and closes the allocation table storage.
        """
        self._handle.remove()
        self._node_monitor_event_handle.remove()
        self._allocation_table.close()

    def _on_allocation_message(self, e):
        # TODO: request validation

        # Centralized allocator cannot co-exist with other allocators; this is a network configuration error.
        if e.transfer.source_node_id != 0:
            logger.warning('[CentralizedServer] Message from another allocator ignored: %r', e)
            return

        # We can't grant allocations as long as there are undiscovered nodes - see specification
        if not self._node_monitor.are_all_nodes_discovered():
            logger.info('[CentralizedServer] Request ignored: not all nodes are discovered')
            return

        # The local state must be reset after the specified timeout
        if len(self._query) and time.monotonic() - self._query_timestamp > CentralizedServer.QUERY_TIMEOUT:
            self._query = bytes()
            logger.info("[CentralizedServer] Query timeout, resetting query")

        # Handling the message
        if e.message.first_part_of_unique_id:
            # First-phase messages trigger a second-phase query
            self._query = e.message.unique_id.to_bytes()
            self._query_timestamp = e.transfer.ts_monotonic

            response = uavcan.protocol.dynamic_node_id.Allocation()  # @UndefinedVariable
            response.first_part_of_unique_id = 0
            response.node_id = 0
            response.unique_id.from_bytes(self._query)
            e.node.broadcast(response)

            logger.debug("[CentralizedServer] Got first-stage dynamic ID request for %s",
                         _unique_id_to_string(self._query))

        elif len(e.message.unique_id) == 6 and len(self._query) == 6:
            # Second-phase messages trigger a third-phase query
            self._query += e.message.unique_id.to_bytes()
            self._query_timestamp = e.transfer.ts_monotonic

            response = uavcan.protocol.dynamic_node_id.Allocation()  # @UndefinedVariable
            response.first_part_of_unique_id = 0
            response.node_id = 0
            response.unique_id.from_bytes(self._query)
            e.node.broadcast(response)
            logger.debug("[CentralizedServer] Got second-stage dynamic ID request for %s",
                         _unique_id_to_string(self._query))

        elif len(e.message.unique_id) == 4 and len(self._query) == 12:
            # Third-phase messages trigger an allocation
            self._query += e.message.unique_id.to_bytes()
            self._query_timestamp = e.transfer.ts_monotonic

            logger.debug("[CentralizedServer] Got third-stage dynamic ID request for %s",
                         _unique_id_to_string(self._query))

            node_requested_id = e.message.node_id
            node_allocated_id = self._allocation_table.get_node_id(self._query)

            # If an ID was requested but not allocated yet, allocate the first
            # ID equal to or higher than the one that was requested
            if node_requested_id and not node_allocated_id:
                for node_id in range(node_requested_id, self._dynamic_node_id_range[1]):
                    if not self._allocation_table.is_known_node_id(node_id):
                        node_allocated_id = node_id
                        break

            # If no ID was allocated in the above step (also if the requested
            # ID was zero), allocate the highest unallocated node ID
            if not node_allocated_id:
                for node_id in range(self._dynamic_node_id_range[1], self._dynamic_node_id_range[0], -1):
                    if not self._allocation_table.is_known_node_id(node_id):
                        node_allocated_id = node_id
                        break

            if node_allocated_id:
                self._allocation_table.set(self._query, node_allocated_id)

                response = uavcan.protocol.dynamic_node_id.Allocation()  # @UndefinedVariable
                response.first_part_of_unique_id = 0
                response.node_id = node_allocated_id
                response.unique_id.from_bytes(self._query)
                e.node.broadcast(response)

                logger.info("[CentralizedServer] Allocated node ID %d to node with unique ID %s",
                            node_allocated_id, _unique_id_to_string(self._query))

                self._query = bytes()   # Resetting the state
            else:
                logger.error("[CentralizedServer] Couldn't allocate dynamic node ID")
