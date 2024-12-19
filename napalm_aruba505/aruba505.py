# -*- coding: utf-8 -*-
"""NAPALM ArubaOS Five zero five Handler."""

import re
import socket
import time
import difflib
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from netmiko import FileTransfer, InLineTransfer
from typing import Union, Generator

import napalm.base.constants as C
import napalm.base.helpers
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    ReplaceConfigException,
    MergeConfigException,
    ConnectionClosedException,
    CommandErrorException,
    CommitConfirmException,
)
from napalm.base.netmiko_helpers import netmiko_args
from napalm.base.helpers import (
    canonical_interface_name,
    transform_lldp_capab,
    textfsm_extractor,
    split_interface,
    abbreviated_interface_name,
    generate_regex_or,
    sanitize_configs,
)
from napalm.base.netmiko_helpers import netmiko_args
from netmiko import ConnectHandler

# Easier to store these as constants
SECONDS = 1
MINUTE_SECONDS = 60
HOUR_SECONDS = 3600
DAY_SECONDS = 24 * HOUR_SECONDS
WEEK_SECONDS = 7 * DAY_SECONDS
YEAR_SECONDS = 365 * DAY_SECONDS


class Aruba505Driver(NetworkDriver):
    """NAPALM ArubaOS [505, 505H, 515] Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.transport = optional_args.get("transport", "ssh")
        self.interfaces = []
        self.archive = str()
        self.new_running_config = str()
        self.config_commands = list()

        # attributes used by config replace
        self.compare_config_has_run = False
        self.pre_change = list()
        self.new_config = list()
        self.pre_change_dict = dict()
        self.new_config_dict = dict()
        self.has_diff = {
            "general": False,
            "snmp": False,
            "radio": False,
            "services": False,
            "manager": False,
            "access_rules": False,
            "ssid_profile": False,
            "auth_survivability": False,
            "auth": False,
            "other": False,
            "wired": False,
            "trailer": False
        }
        self.new_config_commands = dict()

        # Netmiko possible arguments
        self.netmiko_optional_args = netmiko_args(optional_args)

        default_port = {"ssh": 22}
        self.port = optional_args.get("port", default_port[self.transport])
        self.device = None
        self.config_replace = False
        self.interface_map = {}
        self.platform = "cisco_ios"
        self.profile = [self.platform]

    def get_running_config(self):
        _running_config = self.get_config()
        if _running_config:
            return _running_config["running"]

    def switch_to_config_mode(self):
        cmd = f"config terminal"
        self.device.send_command(cmd, expect_string=r"#", read_timeout=90)

    def switch_to_safe_mode(self):
        cmd = f"end"
        self.device.send_command(cmd, expect_string=r"#", read_timeout=90)

    def load_merge_candidate(self, filename=None, config=None):
        """
        1- cache a copy or the current running config in the archive variable
        2- run the commands to alter the current running config
        """
        self.config_replace = False

        _running_config = self.get_running_config()
        if _running_config:
            self.archive = _running_config
        if not _running_config:
            raise ValueError(f"The first copy of old config is not in the cache\n")
        if config:
            self.config_commands = [i for i in config]
        if not config:
            raise ValueError(f"***** No config commands provided! *****\n")

        if self.config_commands:
            # enter config mode
            self.switch_to_config_mode()

            for cmd in self.config_commands:
                self.device.send_command(cmd, expect_string=r"#", read_timeout=90)

            # return to global config mode
            self.switch_to_safe_mode()
            # Save config
            self._send_command("commit apply")
            # Exiting
            self.switch_to_safe_mode()
        if filename:
            raise NotImplementedError

    def load_replace_candidate(
        self, filename: str = None, config: str = None
    ) -> None:
        """
        Aruba Access Point do not have a candidate data store. 
        Therefore, this method loads the new configuration into a class attribute.

        :param filename: Path to the file containing the desired configuration. By default is None.
        :param config: String containing the desired configuration.
        :raise ReplaceConfigException: If there is an error on the configuration sent.
        """
        self.config_replace = True
        new_config = config.split("\n")
        if filename:
            raise NotImplementedError
        # save current running config to startup
        self.device.send_command("commit apply")
        # get current running config
        configs = self.get_config(retrieve="running")
        pre_change = configs.get("running", "").split("\n")
        if not pre_change:
            raise ValueError("Not able to retrieve current running-config.")
        self.new_config = self._cleanup_config(config=new_config)
        self.pre_change = self._cleanup_config(config=pre_change)

    def compare_config(self) -> str:
        """
        Compare the current running-configuration with the new configuration
        loaded through load_merge_candidate or load_replace_candidate and return the diff.
        Produce commands to resolve config diff and save for later execution through commit_config method.
        """
        self.compare_config_has_run = True
        if self.config_replace:
            # diff when loaded by replace method
            diff = []
            # calculate diff for each config part
            self.pre_change_dict = self._slice_config(config=self.pre_change)
            self.new_config_dict = self._slice_config(config=self.new_config)
            for config_part in self.new_config_dict.keys():
                diff_found, _ = self._check_diff(config1=self.pre_change_dict.get(config_part), config2=self.new_config_dict.get(config_part))
                if diff_found:
                    self.has_diff[config_part] = True
            # calculate diff for user output
            diff_found, diff_data = self._check_diff(config1=self.pre_change, config2=self.new_config)
            if diff_found:
                for line in diff_data:
                    diff.append(line)
                # produce list of commands to resolve diff and add to diff output
                diff.append("\n")
                diff.append(f"*"*40)
                diff.append("COMMANDS TO BE EXECUTED TO RESOLVE DIFF:")
                diff.append(f"*"*40)
                for config_part, config_part_cmds in self.new_config_dict.items():
                    # only replace config part, when diff has been found
                    if self.has_diff.get(config_part):
                        commands = self._command_enrichment(config_part=config_part, commands=config_part_cmds)
                        diff.extend(commands)
                        diff.append(f"*"*40)
                        self.new_config_commands[config_part] = commands
                diff.append("write mem\n")
                diff = "\n".join(diff)
            else:
                diff = ""
        else:
            # diff when loaded by merge method
            self.new_running_config = self.get_running_config()
            diff = ""
            if self.archive and self.new_running_config:
                for text in difflib.unified_diff(
                    self.archive.split("\n"), self.new_running_config.split("\n"), n=0
                ):
                    if text[:3] not in ("+++", "---", "@@ "):
                        if diff == "":
                            diff = diff + text
                        else:
                            diff = diff + "\n" + text
            elif not self.archive:
                raise ValueError(f"The old config is not in the cache\n")
            elif not self.new_running_config:
                raise ValueError(f"The current running config is not available\n")
        return diff

    def _slice_config(self, config: list) -> dict:
        """
        Slice configuration into config blocks. Method returns a dictionary.
        """
        config_dict = {
            "general": [],
            "snmp": [],
            "radio": [],
            "services": [],
            "manager": [],
            "access_rules": [],
            "ssid_profile": [],
            "auth_survivability": [],
            "auth": [],
            "other": [],
            "wired": [],
            "trailer": []
        }
        slice_dict = {
            "general": {"start": ":", "end": "", "end_before": ""},
            "snmp": {"start": "snmp-server", "end": "snmp-server", "end_before": ""},
            "radio": {"start": "arm", "end": "", "end_before": "syslog-level"},
            "services": {"start": "syslog-level", "end": "", "end_before": "hash-mgmt-"},
            "manager": {"start": "hash-mgmt-", "end": "hash-mgmt-", "end_before": ""},
            "access_rules": {"start": "wlan access-rule", "end": "", "end_before": ""},
            "ssid_profile": {"start": "wlan ssid-profile", "end": "", "end_before": ""},
            "auth_survivability": {"start": "auth-survivability", "end": "", "end_before": ""},
            "auth": {"start": "mgmt-auth-server", "end": "wlan auth-server", "end_before": ""},
            "other": {"start": "wlan external-captive-portal", "end": "", "end_before": "wired-port-profile"},
            "wired": {"start": "wired-port-profile", "end": "-port-profile", "end_before": ""},
            "trailer": {"start": "", "end": ":"}
        }
        # find indices where to slice list
        slice_start = []
        slice_end = []
        # for separator in separators:
        for key, keywords in slice_dict.items():
            start = keywords.get("start")
            end = keywords.get("end")
            if start == ":":
                # first block
                slice_start.append(0)
                slice_end.append(None)
                continue
            if not any(start in line for line in config):
                # start point not found anywhere in config
                slice_start.append(None)
                slice_end.append(None)
            else:
                start_found_at = 0
                # find start point
                for obj_id, line in enumerate(config):
                    if start in line:
                        slice_start.append(obj_id)
                        start_found_at = obj_id
                        break
                # find end point
                end_found_at = start_found_at
                for obj_id, line in enumerate(config):
                    if obj_id >= start_found_at:
                        # find last line that contains end string
                        if end and end in line:
                            end_found_at = obj_id + 1
                        else:
                            if keywords.get("end_before"):
                                if keywords.get("end_before") in line:
                                    end_found_at = obj_id
                                    break
                            # if end string has not been set,
                            # find either last line that starts like the start line
                            # or last line that is indented and starts with a blank space
                            elif start in line or line.startswith(" "):
                                end_found_at = obj_id + 1
                            else:
                                break
                slice_end.append(end_found_at)
        # set endpoint for first block
        if slice_start[1] > 0:
            slice_end[0] = slice_start[1]
        else:
            slice_end[0] = 0
        # set start/end point for last block
        slice_start[-1] = slice_end[-2]
        slice_end[-1] = len(config)
        if None in slice_start:
            for id, _ in enumerate(slice_start):
                if slice_start[id] == None:
                    # calculate the gap and set missing start/end points
                    last_endpoint = id-1
                    new_start = slice_end[last_endpoint]+1
                    end_id = id+1
                    new_end = slice_start[end_id]-1
                    if new_end > new_start:
                        slice_start[id] = new_start
                        slice_end[id] = new_end
                    else:
                        slice_start[id] = 0
                        slice_end[id] = 0
        # slicing at indices
        start = 0
        for key, start, end in zip(config_dict.keys(), slice_start, slice_end):
            if key == "trailer":
                end == ":"
                config_dict[key] = config[start:end]
            elif start == end and start > 0:
                config_dict[key] = [config[start]]
            elif not end == 0:
                config_dict[key] = config[start:end]
                start = end
        return config_dict

    def _cleanup_config(self, config: list) -> list:
        """ Remove empty lines, trailing blank space"""
        clean_config = []
        remove_lines  = ["conf t", "end", "exit", "version", "virtual-controller-key", "allowed-ap"]
        for line in config:
            line = line.rstrip()
            if line and not any([skipme in line for skipme in remove_lines]):
                clean_config.append(line)
        return clean_config

    def _check_diff(self, config1: list, config2: list) -> Union[bool, Generator[str, None, None]]:
        """ Calculate the diff between 2 config parts"""
        if config1 == None:
            config1 = []
        if config2 == None:
            config2 = []
        diff = difflib.context_diff(config1, config2, n=8)
        try:
            _ = next(diff)
        except StopIteration:
            diff_found = False
        else:
            diff_found = True
        return diff_found, diff

    def _command_enrichment(self, config_part: list, commands: list) -> list:
        """
        Enter config mode and save partial config to running-cfg.
        Adjustments to commands for special cases, e.g. removal of old config, when overwriting is not possible.
        Returns a modified list of commands.
        """
        # if new config is empty, reset to pre-defined defaults
        if not commands:
            commands = []
        commands_at_start = []
        commands_at_end = []
        if config_part == "general":
            commands_at_start.append("no banner motd")
            commands_at_start.append("no allow-new-aps")
        elif config_part == "snmp":
            for line in self.pre_change_dict.get("snmp"):
                if "snmp-server community" in line:
                    commands_at_start.append(f"no {line}")
        elif config_part == "radio":
            commands_at_start.append("no arm")
            # remove existing rf radio profiles
            remove_string = "rf "
            for line in self.pre_change_dict.get("radio"):
                if line.startswith(remove_string):
                    commands_at_start.append(f"no {line}")
            # remove parameter that cannot be removed by no arm cmd
            if any(line == "arm" for line in commands) and not any(line == "80mhz-support" for line in commands):
                commands_at_end.append("arm")
                commands_at_end.append(" no 80mhz-support")
        elif config_part == "services":
            commands_at_start.append("no web-server")
            commands_at_start.append("no allow-rest-api")
        elif config_part == "manager":
            remove_string = "hash-mgmt-user"
            for line in self.pre_change_dict.get("manager"):
                if remove_string in line and not "manager" in line:
                    commands_at_start.append(f"no {line}")
        elif config_part == "access_rules":
            # remove all wired-port-profiles as existing ACL references cannot be modified
            remove_string = "wired-port-profile"
            for line in self.pre_change_dict.get("wired"):
                if remove_string in line and not "wired-SetMeUp" in line and not "E0" in line:
                    commands_at_start.append(f"no {line}")
                elif "enet" in line and "-port-profile" in line and not "enet0" in line:
                    enet_port_profile = line.split()[0]
                    commands_at_start.insert(0, f"no {enet_port_profile}")
            # remove access_rules and all references first
            for line in self.pre_change_dict.get("access_rules"):
                if "wlan access-rule" in line and not "wired-SetMeUp" in line:
                    commands_at_start.append(f"no {line}")
            # add wired-port-profiles again
            commands_at_end = []
            for line in self.new_config_dict.get("wired"):
                # wired-port-profile wired-SetMeUp and E0 is not editable, remove from commands
                if "enet0-port-profile" in line:
                    continue
                if "wired-port-profile wired-SetMeUp" in line or "wired-port-profile E0" in line:
                    skip_parent = True
                elif "-port-profile " in line:
                    skip_parent = False
                if not skip_parent:
                    commands_at_end.append(line)
        elif config_part == "ssid_profile":
            # remove all ssid profiles
            remove_string = "wlan ssid-profile"
            profile_names = []
            for line in self.pre_change_dict.get("ssid_profile"):
                if remove_string in line:
                    profile_names.append(line.split()[-1])
                    commands_at_start.append(f"no {line}")
            # readd ACLs that belong to SSID profiles
            skip_parent = False
            for line in self.new_config_dict.get("access_rules"):
                if line.startswith("wlan access-rule") and any(profile == line.split()[-1] for profile in profile_names):
                    commands_at_start.append(line)
                    skip_parent = False
                elif line.startswith("wlan access-rule"):
                    skip_parent = True
                elif not skip_parent and not "index" in line:
                    commands_at_start.append(line)
        elif config_part == "auth":
            # remove auth servers from wired port profiles
            for line in self.pre_change_dict.get("wired"):
                if "wired-port-profile" in line and not "wired-SetMeUp" in line:
                    remember_parent = line
                if "auth-server" in line and not "wired-SetMeUp" in line:
                    commands_at_start.append(remember_parent)
                    commands_at_start.append(f" no{line}")
            # remove auth servers from ssid profiles
            for line in self.pre_change_dict.get("ssid_profile"):
                if "wlan ssid-profile" in line:
                    remember_parent = line
                if "auth-server" in line:
                    commands_at_start.append(remember_parent)
                    commands_at_start.append(f" no {line}")
            # save, so that references are removed and deletion is permitted
            commands_at_start.append("end")
            commands_at_start.append("commit apply no-save")
            commands_at_start.append("conf t")
            # remove all auth servers
            remove_string = "mgmt-auth-server"
            for line in self.pre_change_dict.get("auth"):
                if remove_string in line:
                    commands_at_start.append(f"no {line}")
            remove_string = "wlan auth-server"
            for line in self.pre_change_dict.get("auth"):
                if remove_string in line:
                    commands_at_start.append(f"no {line}")
            # save, so that references are removed and deletion is permitted
            commands_at_start.append("end")
            commands_at_start.append("commit apply no-save")
            commands_at_start.append("conf t")
            commands_at_end = [line for line in commands if "mgmt-auth-server" in line]
            clean_commands = [line for line in commands if "mgmt-auth-server" not in line]
            commands = clean_commands
            # save each auth server config to maintain the given order
            insert_at_index = []
            for index, command in enumerate(commands):
                if index != 0 and command.startswith("wlan auth-server "):
                    insert_at_index.append(index)
            for index in reversed(insert_at_index):
                commands.insert(index, "conf t")
                commands.insert(index, "commit apply no-save")
                commands.insert(index, "end")
            # add auth servers to wired port profiles again
            for line in self.new_config_dict.get("wired"):
                if "wired-port-profile" in line and not "wired-SetMeUp" in line:
                    remember_parent = line
                if "auth-server" in line and not "wired-SetMeUp" in line:
                    commands_at_end.append(remember_parent)
                    commands_at_end.append(f" {line}")
            # add auth servers to ssid profiles again
            for line in self.new_config_dict.get("ssid_profile"):
                if "wlan ssid-profile" in line:
                    remember_parent = line
                if "auth-server" in line:
                    commands_at_end.append(remember_parent)
                    commands_at_end.append(f" {line}")
        elif config_part == "other":
            for line in self.pre_change_dict.get("other"):
                if "wlan external-captive-portal " in line:
                    commands_at_start.append(f"no {line}")
            commands_at_start.append("no ids")
        elif config_part == "wired":
            # remove all wired-port-profiles
            remove_string = "wired-port-profile"
            profile_names = []
            for line in self.pre_change_dict.get("wired"):
                if remove_string in line and not "wired-SetMeUp" in line and not "E0" in line:
                    commands_at_start.append(f"no {line}")
                    profile_names.append(line.split()[-1])
                elif "enet" in line and "-port-profile" in line and not "enet0" in line:
                    enet_port_profile = line.split()[0]
                    commands_at_start.insert(0, f"no {enet_port_profile}")
            # readd ACLs that belong to wired-port profiles
            skip_parent = False
            for line in self.new_config_dict.get("access_rules"):
                if line.startswith("wlan access-rule") and any(profile == line.split()[-1] for profile in profile_names):
                    commands_at_start.append(line)
                    skip_parent = False
                elif line.startswith("wlan access-rule"):
                    skip_parent = True
                elif not skip_parent and not "index" in line:
                    commands_at_start.append(line)
            # wired-port-profile wired-SetMeUp and E0 is not editable, remove from commands
            clean_commands = []
            for line in commands:
                if "enet0-port-profile" in line:
                    continue
                if "wired-port-profile wired-SetMeUp" in line or "wired-port-profile E0" in line:
                    skip_parent = True
                elif "-port-profile " in line:
                    skip_parent = False
                if not skip_parent:
                    clean_commands.append(line)
            commands = clean_commands
        elif config_part == "trailer":
            commands_at_start.append("no uplink")
            commands_at_start.append("no cluster-security")
        # insert commands to remove features before all other commands
        if commands_at_start:
            commands_at_start += commands
            commands = commands_at_start
        # append commands to re-add features after all other commands
        if commands_at_end:
            commands += commands_at_end
        # add exit command to return from sub-command
        commands_with_exit = []
        last_line_is_subcmd = False
        for line in commands:
            if not line.startswith(" "):
                if last_line_is_subcmd:
                    commands_with_exit.append("exit")
                commands_with_exit.append(line)
                last_line_is_subcmd = False
            else:
                last_line_is_subcmd = True
                commands_with_exit.append(line)
        commands = commands_with_exit
        commands.insert(0, "conf t")
        commands.append("end")
        commands.append("commit apply no-save")
        return commands

    def commit_config(self) -> None:
        """
        Aruba Access Points do not have a candidate data store. Therefore, this method replaces the running
        configuration with the new configuration.
        Hint for usage: Load the new configuration through the load_replace_candidate method first.
        Run compare_config next to find differences per config part.
        Commit_config will only replace the config parts that have changed.
        All changes will be saved to the startup config in the end.
        """
        # run compare_config to produce diff per config part
        if not self.compare_config_has_run:
            self.compare_config()
        if self.config_replace:
            for config_part in self.new_config_dict.keys():
                if self.has_diff.get(config_part):
                    _ = self._send_command(self.new_config_commands.get(config_part, []))
        # permanently save configuration
        # 'commit apply' does not work even though it should according to documentation
        self.device.send_command("write memory")

    def discard_config(self) -> None:
        """
        Discards the configuration loaded into the class attributes and reset.
        """
        self.compare_config_has_run = False
        self.config_replace = False
        self.new_config = list()
        self.new_config_dict = dict()
        self.has_diff = {
            "general": False,
            "snmp": False,
            "radio": False,
            "services": False,
            "manager": False,
            "access_rules": False,
            "ssid_profile": False,
            "auth_survivability": False,
            "auth": False,
            "other": False,
            "wired": False,
            "trailer": False
        }
        self.new_config_commands = dict()

    def open(self):
        """Open a connection to the device."""
        device_type = self.platform
        if self.transport == "telnet":
            device_type = f"{self.platform}_telnet"
        self.device = self._netmiko_open(
            device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Close the connection to the device and do the necessary cleanup."""
        self._netmiko_close()

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {"is_alive": self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {"is_alive": False}

    @staticmethod
    def _show_summary_sanitizer(data):
        """Collects the fqdn and the serial number from the 'show summary'
        :returns a tuple with two values (hostname, fqdn, serial_number)
        """

        fqdn = ""
        serial_number = ""
        hostname_ = ""

        if data:
            data_l = data.strip().splitlines()

            for l in data_l:
                if "Name" in l and not hostname_:
                    hostname_ = f"{l.split(':')[1].lower()}"
                if "DNSDomain" in l and hostname_:
                    fqdn = f"{hostname_}.{l.split(':')[1]}"
                if "Serial Number" in l:
                    serial_number = l.split(":")[1]
        return hostname_, fqdn, serial_number

    @staticmethod
    def _show_version_sanitizer(data):
        """Collects the vendor, model, os version and uptime from the 'show version'
        :returns a tuple with two values (vendor, model, os version, uptime)
        """
        # Initialize to zero
        (years, weeks, days, hours, minutes, seconds) = (0, 0, 0, 0, 0, 0)
        vendor = "Hewlett Packard"
        model = ""
        os_version = ""
        uptime = ""

        if data:
            data_l = data.strip().splitlines()
            for l in data_l:
                if "MODEL" in l:
                    model, os_version = l.split(",")
                if "AP uptime is" in l:
                    tmp_uptime = l.replace("AP uptime is", "").split()
                    uptimes_records = [int(i) for i in tmp_uptime if i.isnumeric()]

                    if uptimes_records and len(uptimes_records) >= 5:
                        weeks, days, hours, minutes, seconds = uptimes_records
                        uptime = float(
                            sum(
                                [
                                    (years * YEAR_SECONDS),
                                    (weeks * WEEK_SECONDS),
                                    (days * DAY_SECONDS),
                                    (hours * HOUR_SECONDS),
                                    (minutes * MINUTE_SECONDS),
                                    (seconds * SECONDS),
                                ]
                            )
                        )
                    if uptimes_records and len(uptimes_records) == 4:
                        weeks, days, hours, minutes = uptimes_records
                        uptime = float(
                            sum(
                                [
                                    (years * YEAR_SECONDS),
                                    (weeks * WEEK_SECONDS),
                                    (days * DAY_SECONDS),
                                    (hours * HOUR_SECONDS),
                                    (minutes * MINUTE_SECONDS),
                                    (seconds * SECONDS),
                                ]
                            )
                        )

        return vendor, model, os_version, uptime

    @staticmethod
    def _send_command_postprocess(output):
        """
        Cleanup actions on send_command() for NAPALM getters.
        Remove "Load for five sec; one minute if in output"
        Remove "Time source is"
        """
        output = re.sub(r"^Load for five secs.*$", "", output, flags=re.M)
        output = re.sub(r"^Time source is .*$", "", output, flags=re.M)
        return output.strip()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd, expect_string=r"#")
                    if "% Parse error" in output:
                        break
            else:
                output = self.device.send_command(command, expect_string=r"#")
            return self._send_command_postprocess(output)
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """
        Get config from device.
        Returns the running configuration as dictionary.
        The candidate and startup are always empty string for now,
        """

        configs = {"running": "", "startup": "No Startup", "candidate": "No Candidate"}

        if retrieve.lower() in ("running", "all"):
            command = "show running-config no-encrypt"
            output_ = self._send_command(command)
            if output_:
                configs["running"] = output_
                data = str(configs["running"]).split("\n")
                non_empty_lines = [line for line in data if line.strip() != ""]

                string_without_empty_lines = ""
                for line in non_empty_lines:
                    string_without_empty_lines += line + "\n"
                configs["running"] = string_without_empty_lines

        if retrieve.lower() in ("startup", "all"):
            command = "show configuration"
            output_ = self._send_command(command)
            if output_:
                configs["startup"] = output_
                data = str(configs["startup"]).split("\n")
                non_empty_lines = [line for line in data if line.strip() != ""]

                string_without_empty_lines = ""
                for line in non_empty_lines:
                    string_without_empty_lines += line + "\n"
                configs["startup"] = string_without_empty_lines
        return configs

    def get_facts(self):
        """Return a set of facts from the devices"""
        interface_list = list(self.get_interfaces().keys())
        configs = {}
        show_version_output = self._send_command("show version")
        show_summary_output = self._send_command("show summary")

        # processing 'show version' output
        configs["show_version"] = show_version_output
        show_version_data = str(configs["show_version"]).split("\n")
        show_version_non_empty_lines = [
            line for line in show_version_data if line.strip() != ""
        ]

        show_version_string_ = ""
        for line in show_version_non_empty_lines:
            show_version_string_ += line + "\n"
        vendor, model, os_version, uptime = self._show_version_sanitizer(
            show_version_string_
        )

        # processing 'show summary' output
        configs["running_"] = show_summary_output
        data = str(configs["running_"]).split("\n")
        non_empty_lines = [line for line in data if line.strip() != ""]

        show_summary_string_ = ""
        for line in non_empty_lines:
            show_summary_string_ += line + "\n"
        hostname_, fqdn_, serial_number_ = self._show_summary_sanitizer(
            show_summary_string_
        )

        return {
            "hostname": str(hostname_),
            "fqdn": fqdn_,
            "vendor": str(vendor),
            "model": str(model),
            "serial_number": str(serial_number_),
            "os_version": str(os_version).strip(),
            "uptime": uptime,
            "interface_list": interface_list,
        }

    def get_lldp_neighbors(self):
        """This code has been tested for HP SW, Cisco FTTX and Nokia ONT"""
        system_name = ""
        interface_description = ""
        lldp = {}

        command = "show ap debug lldp neighbor interface eth0"
        result = self._send_command(command)
        data = [line.strip() for line in result.splitlines()]
        for line in data:
            if line:
                if "System name:" in line:
                    system_name = line.split()[2]
                if "Interface description:" in line:
                    if "Interface description: Not received" in line:
                        interface_description = line.split()[5].replace(",", "")
                    else:
                        interface_description = line.split()[2].replace(",", "")
        lldp["eth0"] = [{"hostname": system_name, "port": interface_description}]
        return lldp

    def sanitize_interface_status(self, data):
        """process the show interface output"""

        new_data = [line.strip() for line in data.splitlines()]
        if new_data:
            for line in new_data:
                if "Admin Status" in line:
                    status = line.split(":")[1]
                    return status

    def _get_interfaces_status(self):
        """This function can be used to get the status of each interface
        in progress"""

        interface_e0_status = self.sanitize_interface_status(
            self._send_command("show wired - port - settings E0")
        )
        time.sleep(1)
        interface_e1_status = self.sanitize_interface_status(
            self._send_command("show wired - port - settings E1")
        )
        time.sleep(1)
        interface_e2_status = self.sanitize_interface_status(
            self._send_command("show wired - port - settings E2")
        )
        time.sleep(1)
        interface_e3_status = self.sanitize_interface_status(
            self._send_command("show wired - port - settings E3")
        )
        time.sleep(1)
        interface_e4_status = self.sanitize_interface_status(
            self._send_command("show wired - port - settings E4")
        )

        return [
            interface_e0_status,
            interface_e1_status,
            interface_e2_status,
            interface_e3_status,
            interface_e4_status,
        ]

    def get_interfaces(self):
        """
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the \
        interfaces in the devices. The inner dictionary will contain the following data for \
        each interface:

         * is_up (True/False)
         * is_enabled (True/False)
         * description (string)
         * last_flapped (float in seconds)
         * speed (int in Mbit)
         * MTU (in Bytes)
         * mac_address (string)
        """
        interfaces = {}

        wired_ports = self._send_command("show wired-port-settings")
        port_regex = r"(?<=-{19}\n)((.|\n)*)(?=Port Profile Assignments)"

        show_interfaces = "show interface"
        interface_data = self._send_command(show_interfaces)
        new_interface_data = [line.strip() for line in interface_data.splitlines()]

        show_ip_interfaces = "show ip interface brief"
        ip_interface_data = self._send_command(show_ip_interfaces)

        remember_parent_line = ""
        for line in new_interface_data:
            if line.startswith("eth"):
                remember_parent_line = line.split()[0]
                interfaces[remember_parent_line] = {
                    "is_up": False,
                    "is_enabled": False,
                    "description": "",
                    "last_flapped": -1.0,
                    "speed": 0,
                    "mtu": 0,
                    "mac_address": ""}
                if "line protocol is up" in line:
                    interfaces[remember_parent_line]["is_up"] = True
                    interfaces[remember_parent_line]["is_enabled"] = True
                elif "line protocol is down" in line:
                    interfaces[remember_parent_line]["is_up"] = False
                    interfaces[remember_parent_line]["is_enabled"] = False
            if line.startswith("Hardware is"):
                interfaces[remember_parent_line]["mac_address"] = line.split()[-1]
            if "Speed" and "duplex" in line:
                speed = line.split()[1]
                if "Mb/s," in speed:
                    speed = speed.replace("Mb/s,", "")
                    interfaces[remember_parent_line]["speed"] = speed

        if wired_ports:
            port_data = re.search(port_regex, wired_ports, re.MULTILINE)
            for line in port_data.group(1).splitlines():
                if not line.startswith("E"):
                    continue
                data_list = line.split()
                interface = data_list[0].replace("E", "eth")
                admin_status = data_list[4]
                speed = data_list[6]
                speed = speed.replace("Mb/s,", "")
                interfaces[interface]["is_enabled"] = True if admin_status == "Up" else False
                # speed taken from 'show interface' output is more acurate, when interface is up
                if interfaces[interface]["is_up"] == False:
                    interfaces[interface]["speed"] = speed

        for line in ip_interface_data.splitlines():
            if line.startswith("Interface  "):
                continue
            line_list = line.split()
            interface = line_list[0]
            # Ignore sub-interfaces
            if not "." in interface:
                interfaces[interface] = {
                    "is_up": True if line_list[5] == "up" else False,
                    "is_enabled": True if line_list[4] == "up" else False,
                    "description": "",
                    "last_flapped": -1.0,
                    "speed": "",
                    "mtu": 0,
                    "mac_address": "",
                }
        return interfaces

    def get_environment(self):
        """
        Get environment facts.
        """
        environment = {}
        mem_cmd = "sh memory"
        cpu_cmd = "show cpu"

        environment.setdefault("cpu", {})
        environment["cpu"][0] = {}
        environment["cpu"][0]["%usage"] = 0.0
        environment.setdefault("memory", {})

        cpu_output = self._send_command(cpu_cmd)
        # process cpu outputs
        data = [
            line.strip() for line in cpu_output.splitlines() if "system" in str(line)
        ]
        current_cpu_usage = 0
        for line in data:
            if line:
                per = line.strip()[-2:-1]
                current_cpu_usage += int(per)

        # process the show memory output
        output_ = self._send_command(mem_cmd)
        available_ram = None
        free_ram = None
        for line in output_.splitlines():
            if "MemTotal:" in line:
                available_ram = int(line.split()[1])
            if "MemAvailable:" in line:
                free_ram = int(line.split()[1])

        environment["cpu"][0]["%usage"] = float(current_cpu_usage)
        environment["memory"]["available_ram"] = available_ram
        environment["memory"]["used_ram"] = available_ram - free_ram

        return environment

    def cli(self, commands):
        """
        Execute a list of commands and return the output or results in a dictionary format
        using the command as the key.
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("\nPlease enter a valid list of commands!\n")

        for command in commands:
            output = self._send_command(command)
            if (
                "Invalid input:" in output
                or "error" in output
                or "Invalid" in output
                or "invalid" in output
            ):
                raise ValueError('Unable to execute command "{}"'.format(command))
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_vlans(self):
        """Get vlans from the device"""

        vlans = {}
        networks = self._send_command("show network")
        wired_ports = self._send_command("show wired-port-settings")
        networks_regex = r"(?<=-{14}\n)((.|\n)*)"
        port_regex = r"(?<=-{19}\n)((.|\n)*)(?=Port Profile Assignments)"
        if wired_ports:
            port_data = re.search(port_regex, wired_ports, re.MULTILINE)
            for line in port_data.group(1).splitlines():
                data_list = line.split()
                vlan_id = data_list[3]
                try:
                    vlan_id = int(vlan_id)
                except ValueError:
                    continue
                interface = data_list[0]
                vlans.setdefault(vlan_id, {"name": "", "interfaces": []})
                interfaces = vlans.get(vlan_id).get("interfaces")
                interfaces.append(interface)
                vlans[vlan_id]["name"] = ""
                vlans[vlan_id]["interfaces"] = interfaces
        if networks:
            nw_data = re.search(networks_regex, networks, re.MULTILINE)
            for line in nw_data.group(1).splitlines():
                data_list = line.split()
                # locate string VLAN to find position of vid
                vlan_index = data_list.index("VLAN") + 1
                vlan_id = data_list[vlan_index]
                try:
                    vlan_id = int(vlan_id)
                except ValueError:
                    continue
                # use SSID as vlan name
                vlan_name = data_list[1]
                vlans.setdefault(vlan_id, {"name": "", "interfaces": []})
                interfaces = vlans.get(vlan_id).get("interfaces")
                interfaces.append(vlan_name)
                vlans[vlan_id]["name"] = vlan_name
                vlans[vlan_id]["interfaces"] = interfaces
        return vlans

    @staticmethod
    def netmask_to_length(netmask):
        """
        Convert subnet mask to prefix length (255.255.255.0 -> /24)
        """
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def get_interfaces_ip(self):
        """
        Returns all configured IP addresses on all interfaces as a dictionary of dictionaries.
        Keys of the main dictionary represent the name of the interface.
        """
        ip_interfaces = {}
        ipv4 = self._send_command("show ip interface brief")
        ipv6 = self._send_command("show ipv6 interface brief")

        for line in ipv4.splitlines():
            if line.startswith("Interface  "):
                continue
            line_list = line.split()
            interface = line_list[0]
            ipv4_addr = line_list[1]
            netmask = line_list[3]
            prefix_length = self.netmask_to_length(netmask)
            ip_interfaces.setdefault(interface, {})
            ip_interfaces[interface].setdefault("ipv4", {})
            ip_interfaces[interface]["ipv4"] = {
                ipv4_addr: {"prefix_length": prefix_length}
            }

        ipv6_list = ipv6.splitlines()[1:]
        ipv6_interfaces = []

        for line in ipv6_list:
            if line.startswith("br"):
                ipv6_interfaces.append(line)
            else:
                ipv6_interfaces[-1] += (";" + line)
        for interface_record in ipv6_interfaces:
            for line in interface_record.split(";"):
                if "line protocol" in line:
                    interface = line.split()[0]
                    ip_interfaces.setdefault(interface, {})
                    ip_interfaces[interface].setdefault("ipv6", {})
                if "subnet is" in line:
                    ipv6_addr_with_len = line.split()[0]
                    ipv6_addr, prefix_length = ipv6_addr_with_len.split("/")
                    prefix_length = prefix_length.replace(",", "")
                    ip_interfaces[interface]["ipv6"] = {ipv6_addr: {"prefix_length": prefix_length}}

        return ip_interfaces


