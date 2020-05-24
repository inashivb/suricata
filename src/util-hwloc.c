/* Entire code has been written taking into consideration the following system topology.
 * It may not work on different topologies.
 *
 * ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ Machine (15GB total)                                                                                          │
 * │                                                                                                               │
 * │ ┌────────────────────────────────────────────────────────────────┐  ├┤╶─┬─────┬─────────────┐                 │
 * │ │ Package L#0                                                    │      │     │ PCI 00:02.0 │                 │
 * │ │                                                                │      │     └─────────────┘                 │
 * │ │ ┌────────────────────────────────────────────────────────────┐ │      │                                     │
 * │ │ │ NUMANode L#0 P#0 (15GB)                                    │ │      ├─────┼┤╶───────┬────────────────┐    │
 * │ │ └────────────────────────────────────────────────────────────┘ │      │0.2       0.2  │ PCI 02:00.0    │    │
 * │ │                                                                │      │               │                │    │
 * │ │ ┌────────────────────────────────────────────────────────────┐ │      │               │ ┌────────────┐ │    │
 * │ │ │ L3 (8192KB)                                                │ │      │               │ │ Net wlp2s0 │ │    │
 * │ │ └────────────────────────────────────────────────────────────┘ │      │               │ └────────────┘ │    │
 * │ │                                                                │      │               └────────────────┘    │
 * │ │ ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │      │                                     │
 * │ │ │ L2 (256KB) │  │ L2 (256KB) │  │ L2 (256KB) │  │ L2 (256KB) │ │      └─────┼┤╶───────┬───────────────────┐ │
 * │ │ └────────────┘  └────────────┘  └────────────┘  └────────────┘ │       3.9       3.9  │ PCI 6e:00.0       │ │
 * │ │                                                                │                      │                   │ │
 * │ │ ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │                      │ ┌───────────────┐ │ │
 * │ │ │ L1d (32KB) │  │ L1d (32KB) │  │ L1d (32KB) │  │ L1d (32KB) │ │                      │ │ Block nvme0n1 │ │ │
 * │ │ └────────────┘  └────────────┘  └────────────┘  └────────────┘ │                      │ │               │ │ │
 * │ │                                                                │                      │ │ 476 GB        │ │ │
 * │ │ ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │                      │ └───────────────┘ │ │
 * │ │ │ L1i (32KB) │  │ L1i (32KB) │  │ L1i (32KB) │  │ L1i (32KB) │ │                      └───────────────────┘ │
 * │ │ └────────────┘  └────────────┘  └────────────┘  └────────────┘ │                                            │
 * │ │                                                                │                                            │
 * │ │ ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │                                            │
 * │ │ │ Core L#0   │  │ Core L#1   │  │ Core L#2   │  │ Core L#3   │ │                                            │
 * │ │ │            │  │            │  │            │  │            │ │                                            │
 * │ │ │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │ │                                            │
 * │ │ │ │ PU L#0 │ │  │ │ PU L#2 │ │  │ │ PU L#4 │ │  │ │ PU L#6 │ │ │                                            │
 * │ │ │ │        │ │  │ │        │ │  │ │        │ │  │ │        │ │ │                                            │
 * │ │ │ │  P#0   │ │  │ │  P#1   │ │  │ │  P#2   │ │  │ │  P#3   │ │ │                                            │
 * │ │ │ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │ │                                            │
 * │ │ │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │  │ ┌────────┐ │ │                                            │
 * │ │ │ │ PU L#1 │ │  │ │ PU L#3 │ │  │ │ PU L#5 │ │  │ │ PU L#7 │ │ │                                            │
 * │ │ │ │        │ │  │ │        │ │  │ │        │ │  │ │        │ │ │                                            │
 * │ │ │ │  P#4   │ │  │ │  P#5   │ │  │ │  P#6   │ │  │ │  P#7   │ │ │                                            │
 * │ │ │ └────────┘ │  │ └────────┘ │  │ └────────┘ │  │ └────────┘ │ │                                            │
 * │ │ └────────────┘  └────────────┘  └────────────┘  └────────────┘ │                                            │
 * │ └────────────────────────────────────────────────────────────────┘                                            │
 * └───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 * ┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 * │ Host: dora                                                                                                    │
 * │                                                                                                               │
 * │ Date: Sun 24 May 2020 02:16:01 PM IST                                                                         │
 * └───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 *
 * Catches:
 * - There may be shorter ways to connect the appropriate NUMA to the network interface.
 * - Code is not generic. Works for the above topology.
 *
 * */

#include "suricata-common.h"
#include "util-debug.h"
#include "util-hwloc.h"
#include "util-device.h"


#ifdef HAVE_HWLOC

void HwlocTopologySetTypeFilter(hwloc_topology_t);
const char *HwlocGetNetworkDeviceName(void);

void HwlocTopologySetTypeFilter(hwloc_topology_t topology)
{
    // IMPORTANT for newer versions else interfaces are not detected
    hwloc_topology_set_type_filter(topology, HWLOC_OBJ_PCI_DEVICE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    hwloc_topology_set_type_filter(topology, HWLOC_OBJ_OS_DEVICE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    hwloc_topology_set_type_filter(topology, HWLOC_OBJ_BRIDGE, HWLOC_TYPE_FILTER_KEEP_IMPORTANT);
    // OR (acc to docs the following should work but it doesnt detect my wifi interface)
    // hwloc_topology_set_io_types_filter(topology, HWLOC_TYPE_FILTER_KEEP_ALL);
}

const char *HwlocGetNetworkDeviceName(void)
{
    int nlive = LiveGetDeviceNameCount();
    SCLogInfo("Number of live devices: %d", nlive);
    const char *live_dev = NULL;
    for (int ldev = 0; ldev < nlive; ldev++) {
        live_dev = LiveGetDeviceNameName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "No live device found");
            return NULL;
        }
    }
    // Since we are just talking about one interface for PoC
    return live_dev;
}

void PrintNUMAnodes(void) {
    hwloc_topology_t topology;
    hwloc_obj_t obj, nobj, cobj;

    // Initialize topology
    hwloc_topology_init(&topology);
    // Set filters required for detection of different types of objects
    // like PCI, Bridge and OS Devices (eth0, etc)
    HwlocTopologySetTypeFilter(topology);

    // Load the topology. This is where the actual detection occurs.
    hwloc_topology_load(topology);

    // Unnecessary but good to match with the topology you see with lstopo
    // on cmdline. If certain objects are missing for some reason, depth may be
    // lower than expected.
    int topodepth = hwloc_topology_get_depth(topology);
    SCLogInfo("Topology depth: %d", topodepth);

    // Basic test
    // 02:00.0 is the bus ID for my WiFi interface
    obj = hwloc_get_pcidev_by_busidstring(topology, "02:00.0");
    if (obj == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "The device with given bus ID was not found");
        goto end;
    }
    // Not sure why name and subtype is NULL.
    // Maybe because the docs say that libpciaccess is required for this and without
    // it info like name etc will be missing.
    SCLogDebug("Hwloc obj name: %s subtype: %s", obj->name, obj->subtype);

    // Get the interface Suricata is running on currently.
    const char *iface = HwlocGetNetworkDeviceName();
    if (iface == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Current network interface name not found");
        goto end;
    }
    SCLogDebug("Current network interface name: %s", iface);

    // Network interfaces are registered as "OS devices" so we find the children
    // from the root which are OS devices.
    for (obj = hwloc_get_next_osdev(topology, NULL); obj; obj = obj->first_child) {
        if (strcmp(obj->name, iface) == 0) {
            SCLogDebug("Found '%s' object in osdev traversal", obj->name);
            // Network interfaces are marked as IO devices (sub: OS devices) which are at times
            // (e.g. my system topology) not a part of a package but outside of the entire
            // Machine object so it needs to find the first non IO ancestor.
            nobj = hwloc_get_non_io_ancestor_obj(topology, obj);
            SCLogDebug("Ancestor obj type: %d", nobj->type);
            // In case the network interface is outside of the entire Machine object like mine
            if (nobj->type == HWLOC_OBJ_MACHINE) {
                SCLogDebug("It is indeed HWLOC_OBJ_MACHINE");
                // Find out the children inside it, NUMA must be there.
                // IMPORTANT: Memory objects are not listed in the main children list,
                // but rather in the dedicated Memory children list.
                for (cobj = hwloc_get_next_child(topology, nobj, NULL); cobj; cobj = hwloc_get_next_child(topology, cobj, NULL)) {
                    SCLogDebug("Child's type: %d", cobj->type);
                    SCLogDebug("Mem arity for cobj: %d", cobj->memory_arity);
                    // Check memory specific first child
                    if (cobj->memory_first_child != NULL) {
                        if (cobj->memory_first_child->type == HWLOC_OBJ_NUMANODE) {
                            SCLogInfo("FOUND THE NUMA node");
                        }
                    }
                }
            }
        } else {
            // If we find another OS Device than the one Suricata is running on
            // then continue to the next OS Device.
            continue;
        }
    }

end:
    hwloc_topology_destroy(topology);
}

#endif /* HAVE_HWLOC */
