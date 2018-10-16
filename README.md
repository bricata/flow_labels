# flow_labels

The flow_labels package provides a mechanism for loading knowledge about a monitored environment into Zeek, using it to enrich Zeek data and making available in script-land for adding smarts to our policy scripts.  That knowledge is captured in the form of labels which are short strings that describe an object in some way.  

Labels are broken down into two categories:  static and dynamic.  Static labels are ingested by Zeek via the Input Framework, where dynamic labels can be added by Zeek scripts during run-time.  

There are two forms of static labels currently supported:  cidr and flow (explained in more detail below).  

###  Installation 

flow_labels is available as a Zeek package.  After installing the Zeek package manager, simply run the command `bro-pkg install flow_labels`.  Next add the load statement `@load flow_labels` to your Site policy file - usually local.bro.  

Any customizations of constants defined by flow_labels can be made in your Site policy file.  At a minimum, this should include redef's of two input file constants *static_cidr_labels* and *static_flow_labels*.  See Configuring Inputs for more information.      

####  Install straight from repo

Use a git client to clone the repo to your local file system.  Ensure the location you clone to is accessible by the user running Zeek.  

`git clone https://github.com/bricata/flow_lables flow_labels`

 If you clone the repo to a location in Zeek's path you can specify the module name only; e.g. `@load flow_labels`.  Alternatively, you can use an absolute path like `@load /opt/zeek_modules/flow_lables`.  For more information about configuring Zeek, see [this](https://www.bro.org/sphinx/components/broctl/README.html#configuration) and [this](https://www.bro.org/sphinx/components/broctl/README.html#option-reference).  

####  Configuring Inputs 

flow_labels uses the Zeek Input Framework to read in label information from two files.   These files are specified by the constants *static_cidr_labels* and *static_flow_labels*.  You should add redef statements to your Site policy file to point these constants to the correct filesystem locations for each file.  For example:

```
redef flow_labels::static_cidr_labels = "/opt/zeek_inputs/cidr.labels";
redef flow_labels::static_flow_labels = "/opt/zeek_inputs/flow.labels"; 
```
