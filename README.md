# IP-Reassembly

## The base processing 
Create the queue for processing the ip fragments,every ip group (has the same fragment ID) needs a node , this node points to a list of the fragments that in the same group. When all the fragments of the list arrive, we need reassemble the list, or the queue that existint is more than 30s,free the list.

## The functions that needs for the reassemble

* struct ipacket *ip_defrag(struct ipacket *packet): when a fragment arrives,try to reassemble the packet, return value maybe a ipacket or NULL
* void ip_frag_queue(struct ipq *qp, struct ipacket *packet,uint16_t offset): when a packet comes , try to insert it into the queue list
* struct ipacket *ip_frag_reasm(struct ipq *qp): This function accomplishes the reassembling process that is the queue list pq
* void ipq_put(struct ipq *ipq): This function frees the list that the queue ipq points to. To use this function when the reassembling process ends or the queue list exising time is out.
* uint16_t  que_length(struct ipq *qp): To calculate the data length of the IP fragment list

