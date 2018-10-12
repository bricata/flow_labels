# flow_labels

The flow_labels package provides a mechanism for loading knowledge about a monitored environment into Zeek, using it to enrich Zeek data and making available in script-land for adding smarts to our policy scripts.   


# Inputs 
flow_labels makes use of two designated input files: cidr.labels and flow.labels. These files are ingested by Zeek's Input Framework. 

