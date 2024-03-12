<!DOCTYPE html>

<h2>Napalm-aruba505 </h2> <br>

<h3>Driver implementation for ArubaOS Access Points</h3> <br>

<h5>Currently supported Napalm methods:</h5>


<div>
    <ul> get_config() </ul>
    <ul> get_facts() </ul>
    <ul> get_lldp_neighbors </ul>
    <ul> get_interfaces </ul>
    <ul> get_interfaces_ip </ul>
    <ul> get_environment </ul>
    <ul> get_vlans </ul>
    <ul> get_running_config() </ul>
    <ul> is_alive </ul>
</div>


<h5>How to install</h5>

<ul>pip install napalm-aruba505</ul>


<h5>How to use it</h5>
<ul>
    <li>import napalm</li>
    <li>from napalm import get_network_driver</li>
    <li>driver = napalm.get_network_driver("napalm_aruba505")</li>
    <li>device = driver("my-ap-1", "my_username", "my_password")</li>
    <li>config = device.get_config()</li>
    <li>print(config)</li>
</ul> <br>
