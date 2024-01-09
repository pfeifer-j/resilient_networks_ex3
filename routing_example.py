#!/usr/bin/env python
import argparse
from collections import defaultdict
from pathlib import Path
from bgpdumpy import BGPDump, TableDumpV2
import ipaddress
import json

ROUTING_TABLE_DIR = Path()  # "./"
ASN_TO_FILTER = 64475  # AS64475


def get_routing_table_entries(f, asn):
    export_file = ROUTING_TABLE_DIR / "{:s}-{:d}.json".format(f.name, asn)
    # Reload table if possible
    if export_file.exists():
        print("Reading cache for ASN {:d} from '{!s}'".format(asn, export_file))
        with open(export_file, 'r') as jf:
            for ip_prefix, route_path in json.load(jf):
                yield ip_prefix, route_path
        return

    print("The first execution might take several minutes to parse the BGP Dump.")  # 3m16.955s
    print("Subsequents executions will leverage a cache for faster processing")  # 0m10.616s
    with BGPDump(f) as bgp:
        routes = list()
        for entry in bgp:

            # assume export to be pf type TableDumpV2
            assert isinstance(entry.body, TableDumpV2)

            # Filter global table entries of a specific AS
            for route in entry.body.routeEntries:
                if route.peer.peerAS != asn:
                    continue

                # Get a CIDR representation of this prefix
                prefix = '%s/%d' % (entry.body.prefix, entry.body.prefixLength)

                table_entry = (prefix, route.attr.asPath.split()[1:])
                routes.append(table_entry)
                yield table_entry

    # Save for next run
    with open(export_file, 'w') as jf:
        # print("Writing cache for ASN {:d} to '{!s}'".format(asn, export_file))
        json.dump(routes, jf)


def main(f):
    routes_count = 0
    avg_path_len = 0
    biggest_prefix = 32
    asses_occurrences = defaultdict(int)
    directly_connected_asses = 0
    origin_as_for_networks = defaultdict(list)
    asns_set = set()
    prefix_origin = set()
    transit_ases = set()

    # Iterate the routing table entries of a specific AS
    for prefix, route_path in get_routing_table_entries(f, ASN_TO_FILTER):
        # Check for IPv4
        ip_prefix = ipaddress.ip_network(prefix)
        if not isinstance(ip_prefix, ipaddress.IPv4Network):
            continue

        # ------------------------------- #
        # PUT YOUR CUSTOM ANALYSIS HERE...
        # 1.2
        # routes_count += 1

        # 2.1
        # if(len(route_path) == 0):
        #    print('%s -> %s' % (prefix, route_path))

        # 2.2.1
        # if(len(route_path) != 0):
        #    routes_count += 1
        #    avg_path_len = avg_path_len + len(route_path) 

        # 2.2.2
        # if(len(route_path) != 0):
        #    current_prefix = eval(prefix.split("/")[1])

        #    if(biggest_prefix > current_prefix):
        #        biggest_prefix = current_prefix

        # 2.2.4
        # if(len(route_path) != 0):
        #    asns_set.update(route_path)

        # 2.2.5
        if (len(route_path) != 0):
            prefix_origin.update(route_path[-1])
            transit_ases.update(route_path[:-1])

        # 3.1
        if (len(route_path) == 1):
            directly_connected_asses += 1
        # 3.2
        if (len(route_path) > 0):
            for key in route_path:
                asses_occurrences[key] += 1

        # 3.3
        if len(route_path) > 0:
            if route_path[-1] in origin_as_for_networks:
                try:
                    examined_network = ipaddress.IPv4Network(prefix)
                except ValueError:
                    examined_network = ipaddress.IPv6Network(prefix)
                networks = origin_as_for_networks[route_path[-1]]
                for network in networks:
                    try:
                        converted_network = ipaddress.IPv4Network(network)
                    except ValueError:
                        converted_network = ipaddress.IPv6Network(network)
                    if prefix in origin_as_for_networks[route_path[-1]]:
                        print("Network {} is already in the list".format(network))
                        break
                    if examined_network.supernet_of(converted_network):
                        origin_as_for_networks[route_path[-1]].remove(network)
                        origin_as_for_networks[route_path[-1]].append(prefix)
                    elif not examined_network.subnet_of(converted_network):
                        origin_as_for_networks[route_path[-1]].append(prefix)

            else:
                origin_as_for_networks[route_path[-1]].append(prefix)

        # 3.4

    # Report analysis results
    # print("Number of routes: {:d}".format(routes_count))
    # print("Avg path length: {:.2f}".format(avg_path_len/routes_count))
    # print("Largest prefix: {:d}".format(biggest_prefix))
    # print("Unique ASNs among all routes: {}".format(len(asns_set)))
    print("Number of prefix origins: {}".format(len(prefix_origin)))
    print("Number of transit ASes: {}".format(len(transit_ases)))
    print("Number of pure transit ASes: {}".format(len(transit_ases - prefix_origin)))
    print("Number of directly connected ASes: {}".format(directly_connected_asses))
    most_frequent_as = max(asses_occurrences, key=asses_occurrences.get)
    print("AS {} occurs {} times, and is the most critical AS in terms of frequency".format(most_frequent_as,
                                                                                            asses_occurrences[
                                                                                                most_frequent_as]))


if __name__ == '__main__':
    # Commandline Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("tabledumpfile", help="path to the bview file")
    args = parser.parse_args()

    # Analyze export file
    file_path = Path(args.tabledumpfile)
    main(file_path)
