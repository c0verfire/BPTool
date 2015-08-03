# bp-tool-0.6(Dublin)

The Palo Alto Best Practices Tool is a script that is used to assess Best Practice Configurations on Palo Alto Firewalls.

<h2>New to version 0.6!!</h2>
<ul>
<li>Rule BP01012 - Forbid the use of password profiles. <br>
<li>Rule BP01013 - Adjust Max Rows in CSV and User Activity Reports to 1048576. <br>
<li>Rule BP01018 - Validate that the default admin password has been changed. <br>
<li>Rule BP04009 - Configure Firewall System Logs to Forward to Panorama, Syslog, SNMP, or eMail. <br>
<li>Rule BP04010 - Configure Firewall Config Logs to Forward to Panorama, Syslog, SNMP, or eMail. <br>
<li>Rule BP04014 - Require a fully-synchronized High Availability peer <br>
<li>Rule BP04015 - For High Availability, require Link Monitoring, Path Monitoring, or both <br>
<li>Rule BP04016 - Forbid simultaneously enabling the Preemptive option, and configuring the Passive Link State to shutdown simultaneously. (For an HA pair) <br>
<li>Rule BP04017 - Require IP-to-username mapping for user traffic <br>
<li>Rule BP04018 - Disable WMI probing if not required. <br>
<li>Rule BP04019 - Forbid User-ID on external and other non-trusted zones <br>
<li>Rule BP04020 - Require the use of User-ID’s Include/Exclude Networks section, if User- ID is enabled. Include only trusted internal networks. <br>
<li>Rule BP04021 - Require default Log Forwarding Profile, this will be added automatically to all new Security Policies <br>

<li>Created Rule Group 10000 - 13999 for Device Group and Device Template Panorama Rules.  <br>
</ul>


<br>

<h2>Bug Fixes version 0.6</h2>
<ul>
<li>Fixed a bug in the conditional cell formatting that offset the cell coloring in Column E
</ul>
