# OpenFlow application – a web server load balancer
A load balancer application deployed on RYU controller to perform load-balancing across servers using Python.

IP packets from each one of the client hosts (h3, h4, h5, h6) to 10.0.0.100 (virtual IP) are sent to h1 (10.0.0.1) host or h2 (10.0.0.2) 
host based on the clients’ hosts MAC addresses. If the integer value of the MAC address of the client is odd (client-MAC-Address % 2 == 1) 
it will be sent to h1, otherwise to h2.
