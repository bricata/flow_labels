#
### @GUI@ Apply host and flow labels to connections.
#

#! Flow Labels
#!
#! This script provides a mechanism for managing and using institutional 
#! knowledge about a monitored environment to make informed observations 
#! of normal and abnormal network activity.  
#!   

#@load flow_analysis/calculate_pcr

module flow_labels;

export  {

    redef enum Log::ID += {
        LOG
    };

    # Record for storing labels for a connection 
    type conn_fields: record {
        orig: set[string] &optional &log;
        resp: set[string] &optional &log;
        flow: set[string] &optional &log;
        known: bool &optional &log;
        authorized: bool &optional &log;
        suspicious: bool &optional &log;
    };

    # Record for logging string label fields only
    type conn_labels: record {
        orig: set[string] &optional &log;
        resp: set[string] &optional &log;
        flow: set[string] &optional &log;
    };

    redef record Conn::Info += {
        labels: conn_labels &log &optional;
    };

    redef record Conn::Info += {
        pcr: double &log &optional;
    };


    # Add conn_fields container to the connection record
    # Use this for dynamic labeling throughout the connection's lifecycle  
    redef record connection += {
        labels: conn_fields &optional;
    };

    # Record for writing labeled flows to the log stream
    type Info: record {
        ts: time &log;
        cluster_node: Cluster::NodeType &log;
        #proto: transport_proto &optional &log;
        #orig_h: addr &optional &log;
        #orig_p: count &optional &log;
        #resp_h: addr &optional &log;
        #resp_p: count &optional &log;
        uid: string &optional &log;
        #pcr: string &optional &log;
        labels: conn_fields &optional &log;
    };

    # Record definition for a CIDR labels datafile entry
    type cidr_label_entry: record {
        address: string;
        labels: string;
    };

    # Record definition for a Flow labels datafile entry
    type flow_label_entry: record {
        # Transport protocol
        proto:      transport_proto &optional;
        # Connection originator IP
        orig_h:     string &optional;
        # Connection originator port
        orig_p:     string &optional;
        # Connection's Producer Consumer Ratio
        pcr:        string &optional;
        # Connection responder IP
        resp_h:     string &optional;
        # # Connection responder port
        resp_p:     string &optional;
        # Is the flow known? e.g. has it been analyzed?
        known:          bool &optional;
        # Is the flow authorized?  e.g. known and intentionally permitted? 
        authorized:     bool &optional;
        # Is this flow always considered suspicious?
        suspicious:     bool &optional;
        # Meta-tags that describe the flow 
        labels:          string &optional;
    };

    # Record to describe a flow's unique attributes
    type flow_id: record {
        # Transport protocol 
        proto:      transport_proto &optional;
        # Originator IP address (or subnet)
        orig_h:     subnet &optional;
        # Originator port, number only
        orig_p:     count &optional;
        # Direction of data flow, if any. See flow direction indicators
        pcr:        string &optional;
        # Responder IP address (or subnet)
        resp_h:     subnet &optional;
        # Responder port, number only
        resp_p:     count &optional;
    };

    # Record for flowkb entries 
    type flow_meta: record {
        labels: set[string] &optional &log;
        known: bool &default=F &log;
        authorized: bool &optional &log;
        suspicious: bool &optional &log;
    };

    # Record for cidr_kb entries
    type cidr_labels: record {
        static: set[string] &optional;
        dynamic: set[string] &optional &create_expire=11 mins;
    };

    # Available logging modes
    type logging_modes: enum {
        # Disable logging 
        log_none,
        # Log all 
        log_all,
        # Log any known flow, both authorized and unauthorized
        log_known_only,
        # Log any unknown flow. Most useful for network baselining and ongoing monitoring.
        log_unknown_only,
        # Log only known, authorized flows.  Generally these are the least interesting.
        log_known_and_authorized,
        # Log any flow we consider known but unauthorized.  Useful for policy enforcement monitoring. 
        log_known_and_unauthorized
    };

    # Configure logging mode (or disable)
    # This value determines which flows will be logged, see logging_modes for options. log_none turns of logging  
    const logging_mode = log_none &redef;

    # Tokenization pattern for entries in a data file
    #  break up strings on: commas, spaces and 2 or more sequential periods
    const token_pattern = /,*| *|\.\.+/;

    # Basic pattern for identifying possible CIDR notation 
    const cidr_regex: pattern = /\/[0-9]{1,3}$/;

    # Pattern for reserved, non-private IP addresses
    global reservedip_regex: pattern = /^255\.|\.255$|^239\.|^224\.|^0\.|^127.0|^169\.254/;

    # Absolute path to CIDR label data file 
    const static_cidr_labels = "/opt/zeek_inputs/cidr.labels" &redef;

    # Absolute path to Flow label data file 
    const static_flow_labels = "/opt/zeek_inputs/flow.labels" &redef;

    # Host/subnet knowledge base 
    global cidr_kb: table[subnet] of cidr_labels = {} &synchronized;

    # Flow knowledge base 
    global flow_kb: table[flow_id] of flow_meta = {} &synchronized;

    # Triggered when an label file has been read
    global read_label_done: event();

    # Triggered when flow_label matches are logged
    global log_labeled_flow: event(f: flow_labels::Info);

    # Event for applying flow_label analysis rules
    global flow_labeled: event(c: connection);

    # Event for reading flow label data file entries
    global read_flow_labels: event(desc: Input::EventDescription, tpe: Input::Event, fi: flow_labels::flow_label_entry);

    # Event for reading flow label data file entries
    global read_cidr_labels: event(desc: Input::EventDescription, tpe: Input::Event, ci: flow_labels::cidr_label_entry);

    # Set of flow direction indicators for representing the direction of 
    # data flow between the originator and responder of a given connection.  
    # Flow Direction Indicators: 
        ## >    Data flow from orig to resp, pcr >= 0.01
        ## <    Data flow from resp to orig, pcr =< -0.01
        ## =    Data flow is equal or nearly equal, pcr < 0.01 && > -.01 
    const direction_indicators: set[string] = { ">", "<", "=" }; 

    # Retrieve label for a given IP
    global get_cidr_labels: function(host: addr): set[string];

    # Retrieve label for a given flow
    global get_flow_labels: function(c: connection): flow_meta;

    # Check a host's cidr_kb entry for a term
    global ip_has_label: function(host: addr, terms: set[string]): bool;

    # Add dynamic labels to a cidr_kb entry 
    global add_ip_label: function(l: string, a: addr);

    # Convert an IP specified as a string into a subnet (CIDR)
    global to_cidr: function(address: string): subnet;

}

# Convert IP strings to subnets
function to_cidr(address: string): subnet {
    local n: subnet = [::]/0;

    if ( is_valid_ip(address) ) {
        local a: addr = to_addr(address);

        if ( is_v4_addr(a) ) {
            n = to_subnet(cat(a) + "/32");
            return n;
        }
        else if ( is_v6_addr(a) ) {
            n = to_subnet(cat(a) + "/128");
            return n;
        }
        else {
            Reporter::warning(fmt("IP address [%s] does not appear to be v4 or v6. Unable to convert to CIDR format.", address));
            return n;
        }
    }
    else if ( cidr_regex in address ) {
        n = to_subnet(address);
        return n;        
    }
    else {
        Reporter::warning(fmt("Unable to convert %s to CIDR format.", cat(address)));
        return n;
    }
} 

# Determine if a PCR value matches the provided rule
function is_pcr_match(pcr_rule: string, pcr: double): bool {
    # The pcr is a ratio used to quickly measure data flow, or the 
    # amount of bytes transferred vs received in a network session
    # between two endpoints.  
    # 
    # The pcr field in the flow_labels can contain one of the 
    # three directional indicators 
    local res: bool = F;
    if (pcr_rule !in direction_indicators ) {
        return res;
    }

    #   If flow is orig -> resp, pcr > 0.01
    if ( pcr_rule == ">" && pcr >= 0.01 ) {
        res = T;
    }
    #   Data flow is orig <- resp, pcr < 0.0
    else if ( pcr_rule == "<" && pcr <= -0.01 ) {
        res = T;
    }
    #   Data flow orig->resp, pcr > 0.0
    else if ( pcr_rule == "=" && pcr > -0.01 && pcr > 0.01 ) {
        res = T;
    }
    
    return res;
}

#  Add a label to an IP in the cidr_kb  
function add_ip_label(l: string, a: addr)
    {
    # If a kb entry already exists, add to the set of labels
    if ( a in cidr_kb )
        add cidr_kb[a]$dynamic[l];
    else
        {
        cidr_kb[a] = cidr_labels();
        cidr_kb[a]$dynamic = set(l);
        add cidr_kb[a]$dynamic[l]; 
        }
    }

# Check if an IP has a specified label 
function ip_has_label(host: addr, terms: set[string]): bool
    {
    # Check if an IP has the listed labels
    local need = |terms|;
    local found = 0;

    if ( host in cidr_kb ) {
        for ( net in cidr_kb ) {
            if ( host in net ) {
                for ( t in terms ) {
                    local s = to_lower(strip(t));
                    if ( s in cidr_kb[net]$static ) {
                        found += 1;
                    } else if ( s in cidr_kb[net]$dynamic ) {
                        found += 1;
                    }
                }
            }
        }
    }

    return need == found;
}

#  Check if a connection has matching labels  
function conn_has_label(c: connection, terms: set[string]): bool 
    {
    local orig_p = port_to_count(c$id$orig_p);
    local resp_p = port_to_count(c$id$resp_p);

    for ( entry in flow_kb )
        {
        # check the proto first, eliminates 2/3 of the kb
        if ( entry?$proto && entry$proto != c$conn$proto ) {
            next;
        }
        else if ( entry?$orig_h && c$id$orig_h !in entry$orig_h ) {
            # skip if orig IP not a match
            next;
        }
        else if ( entry?$resp_h && c$id$resp_h !in entry$resp_h ) {
            # skip if resp IP not a match
            next;
        }
        else if ( entry?$orig_p &&  entry$orig_p != orig_p ) {
            # skip if the orip port is defined and not a match
            next;
        }
        else if ( entry?$resp_p &&  entry$resp_p != resp_p ) {
            # skip if the orip port is defined and not a match
            next;
        }
        else if ( entry?$pcr && c$conn?$pcr ) {
            # Check pcr rule for a match, skip if not
            if ( ! is_pcr_match(entry$pcr, c$conn$pcr) ) {
                next;
            }
        }
        else 
            {
            if ( flow_kb[entry]?$labels && |flow_kb[entry]$labels| > 0 )
                {
                for ( t in terms )
                    {
                    local s = to_lower(strip(t));
                    if ( s in flow_kb[entry]$labels )
                        return T;
                    }    
                }
            }
        }
    
    # No matching label found, return F
    return F;
    }

# Retrieve flow labels for a given connection 
function get_flow_labels(c: connection): flow_meta {
    local fm = flow_meta();
    fm$labels = set();

    local orig_p = port_to_count(c$id$orig_p);
    local resp_p = port_to_count(c$id$resp_p);

    for ( entry in flow_kb ) {
        # check the proto first, eliminates 2/3 of the kb
        if ( entry?$proto && entry$proto != c$conn$proto ) {
            next;
        }
        else if ( entry?$orig_h && c$id$orig_h !in entry$orig_h ) {
            # skip if orig IP not a match
            next;
        }
        else if ( entry?$resp_h && c$id$resp_h !in entry$resp_h ) {
            # skip if resp IP not a match
            next;
        }
        else if ( entry?$orig_p &&  entry$orig_p != orig_p ) {
            # skip if the orip port is defined and not a match
            next;
        }
        else if ( entry?$resp_p &&  entry$resp_p != resp_p ) {
            # skip if the orip port is defined and not a match
            next;
        }
        else if ( entry?$pcr && c$conn?$pcr ) {
            # Check pcr rule for a match, skip if not
            if ( ! is_pcr_match(entry$pcr, c$conn$pcr) ) {
                next;
            }
        }
        else {
            if ( flow_kb[entry]?$known )
                {
                fm$known = flow_kb[entry]$known;                
                }

            if ( flow_kb[entry]?$authorized )
                {
                fm$authorized = flow_kb[entry]$authorized;    
                }

            if ( flow_kb[entry]?$suspicious )
                {
                fm$suspicious = flow_kb[entry]$suspicious;
                }
            
            if ( flow_kb[entry]?$labels && |flow_kb[entry]$labels| > 0 ) {
                for ( term in flow_kb[entry]$labels ) {
                    add fm$labels[term];
                }
            }
        }
    }

    # Return the flow's meta Information
    return fm;
}

# Retrieve all labels for a given IP address from the cidr_kb
function get_cidr_labels(host: addr): set[string]
    {
    local clabels: set[string] = set();
    if ( host in cidr_kb ) {
        for ( net in cidr_kb ) { 
            if ( host in net ) {
                for ( term in cidr_kb[net]$static ) {
                    if ( term != "" ) {
                        add clabels[term];
                    }
                }
                for ( term in cidr_kb[net]$dynamic ) {
                    if ( term != "" ) {
                        add clabels[term];
                    }
                }
            }
        }
    }

    return clabels;
}

#  Initialize label containers for each connection.  
event new_connection(c: connection)
    {
    c$labels = conn_fields();
    c$labels$orig = set();
    c$labels$resp = set();
    c$labels$flow = set();
    }

#  Register to receive the needed events on the Manager node 
# event  remote_connection_established(p: event_peer) {
#    if ( Cluster::local_node_type() == Cluster::MANAGER ) { 
#        # When a worker connects register for the appropriate events 
#        if ( p?$class && /worker/ in p$class ) {
#            request_remote_events(p, /^connection_state_remove/);
#        }
#    }
#}

# Set up the labels log stream
event bro_init() {
    if ( logging_mode != log_none ) {
        Log::create_stream(flow_labels::LOG, [$columns=Info, $ev=log_labeled_flow, $path="labeled_flows"]);
    }
}

# Add PCR to all connections 
event connection_state_remove (c: connection) &priority=3
    {

    if ( ! c$conn?$orig_bytes && ! c$conn?$resp_bytes ) {
        return;
    }
    else if (c$conn$orig_bytes == 0 && c$conn$resp_bytes == 0 ) {
        c$conn$pcr = 0.0;
    }
    else {
        local n = (c$conn$orig_bytes + 0.0) - (c$conn$resp_bytes + 0.0);
        local d = (c$conn$orig_bytes + 0.0) + (c$conn$resp_bytes + 0.0);

        local x = ( n / d );
        c$conn$pcr = x;
    }
}

#  Add static labels at the end of the connection 
event connection_state_remove(c: connection) &priority=0 {
    
    # If the labels field doesn't exist we have a partial connection.
    # Dynamic labeling didn't happen but we still enrich with static
    # labels.  
    if ( ! c?$labels )
        {
        c$labels = conn_fields();
        c$labels$orig = set();
        c$labels$resp = set();
        c$labels$flow = set();
        }   

    local orig_labels = get_cidr_labels(c$id$orig_h);
    local resp_labels = get_cidr_labels(c$id$resp_h);
    
    Reporter::info(fmt("%d labels found for %s and %d for %s", |orig_labels|, |resp_labels|, c$id$orig_h, c$id$orig_h));

    local fm = get_flow_labels(c);

    Reporter::info(fmt("%d labels found for uid %s", |fm|, c$uid));

    # add orig_labels to the set 
    if ( |orig_labels| > 0 )
        {
        for ( ol in orig_labels )
            {
            add c$labels$orig[ol];
            }    
        }
    
    # add resp_labels to the set
    if ( |resp_labels| > 0 )
        {
        for ( rl in resp_labels)
            {
            add c$labels$resp[rl];
            }    
        }
    
    # add flow labels to the set 
    for ( fl in fm$labels )
        {
        add c$labels$flow[fl];
        }

    # if authorized and authorized not exist in conn, add it
    if ( fm?$authorized && ! c$labels?$authorized )
        {
        c$labels$authorized = fm$authorized;
        }

    # if known and known not exist in conn, add it
    if ( fm?$known && c$labels?$known )
        {
        c$labels$known = fm$known;
        }

    # if suspicious and suspicious not in conn, add it 
    if ( fm?$suspicious && c$labels?$suspicious )
        {
        c$labels$suspicious = c$labels$suspicious;
        }
   
    # Generate flow_labeled event for handling enriched flows elsewhere 
    event flow_labeled(c);

    # If logging is disabled, enrich the conn log and stop here
    if ( logging_mode == log_none ) 
        {
        c$conn$labels = conn_labels();
        c$conn$labels$orig = set();
        c$conn$labels$resp = set();
        c$conn$labels$flow = set();

        if ( |orig_labels| > 0 )
            {
            for ( ol in orig_labels )
                {
                add c$conn$labels$orig[ol];
                }    
            }
        
        # add resp_labels to the set
        if ( |resp_labels| > 0 )
            {
            for ( rl in resp_labels)
                {
                add c$conn$labels$resp[rl];
                }    
            } 
        
        # add flow labels to the set 
        for ( fl in fm$labels )
            {
            add c$conn$labels$flow[fl];
            }

        return;
        }
    
    # Don't log any traffic to/from a non-private, reserved IP range
    if ( reservedip_regex in cat(c$id$orig_h) || reservedip_regex in cat(c$id$resp_h) ) {
        return;
    }
  
    # Check the logging mode and evaluate the known and authorized fields to determine if the flow 
    # should be written to the log stream.  Assume no, unless the right conditions are met.   
    local write_log = F;

    # Log only known, authorized flows (these are the least interesting to us)
    if ( logging_mode == log_all && (|c$labels$orig| > 0 || |c$labels$resp| > 0 || |c$labels$flow| > 0 ))
        write_log = T;
    else if ((logging_mode == log_known_and_authorized) && 
        (c$labels?$known && c$labels$known == T && c$labels?$authorized && c$labels$authorized == T))
        write_log = T;
    # Log any known flow, both authorized and unauthorized.   
    else if (logging_mode == log_known_only && c$labels?$known && c$labels$known == T) 
        write_log = T;
    # Log any unknown flow. Baselining and ongoing monitoring. 
    else if (logging_mode == log_unknown_only && c$labels?$known && c$labels$known == F)
        write_log = T;
    # Log any flow we consider known but unauthorized.  Useful for policy enforcement
    else if (logging_mode == log_known_and_unauthorized && 
            (c$labels?$known && c$labels$known == T && c$labels?$authorized && c$labels$authorized == F))
        write_log = T;

    if ( ! write_log ) 
        {
        return;
        }

    # populate the flow_label Info record and write it to log
    local match = flow_labels::Info(
        $ts = c$start_time,
        $cluster_node = Cluster::local_node_type(),
        $uid = c$uid,
        $labels = c$labels
    );

    Log::write(flow_labels::LOG, match);
}

@if ( Cluster::local_node_type() == Cluster::MANAGER )
# Process entries in the cidr.labels file 
event read_cidr_labels(desc: Input::EventDescription, tpe: Input::Event, ci: flow_labels::cidr_label_entry) {
    
    if ( ! ci?$address ) {
        Reporter::warning("Encountered CIDR label entry that was missing an address value.");
        return;
    }

    if ( ! ci?$labels ) { 
        Reporter::warning("Encountered CIDR label entry that was missing the labels value.");
        return;   
    }

    local n = to_cidr(ci$address);

    if ( n != [::]/0 ) {

        if ( n !in cidr_kb )
            {
            cidr_kb[n] = cidr_labels();
            cidr_kb[n]$static = set();
            cidr_kb[n]$dynamic = set();
            }
            
        if ( token_pattern in ci$labels ) {
            local labels = split_string(to_lower(strip(ci$labels)), token_pattern);
            for ( i in labels ) {
                if ( |labels[i]| > 0 ) {
                    add cidr_kb[n]$static[strip(labels[i])];
                }
            }
        }
        else {
            add cidr_kb[n]$static[to_lower(ci$labels)];    
        }
    }
    else { 
        Reporter::warning("Problem converting CIDR label address into a subnet. Check the cidr.label datafile.");
    }
}

# Process entries in the flow.labels file 
event read_flow_labels(desc: Input::EventDescription, tpe: Input::Event, fi: flow_labels::flow_label_entry) {
    local fid = flow_id();
    # Reporter::Info(fmt("%s", cat(fi)));

    # read the protocol: tcp, udp or icmp
    if ( ( fi?$proto ) && ( fi$proto == tcp || fi$proto == udp || fi$proto == icmp ) ) {
        fid$proto = fi$proto;
    } 
    
    local includes_ip = F;
    # read the orig address
    if ( fi?$orig_h && fi$orig_h != "") {
        local osn = to_cidr(fi$orig_h); 
        if ( osn != [::]/0 ) {
            fid$orig_h = osn;
            includes_ip = T;
        } 
    }

    # read the resp address
    if ( fi?$resp_h && fi$resp_h != "") { 
        local rsn = to_cidr(fi$resp_h);
        if ( rsn != [::]/0 ) {
            fid$resp_h = rsn;
            includes_ip = T;
        }
    }

    # Do not create the flow KB entry if there isn't at least one valid IP
    if ( includes_ip == F ) {
        return;
    }

    # read the orig port
    if ( fi?$orig_p ) { 
        fid$orig_p =  to_count(fi$orig_p);
    }

    # read the flow pcr rule value
    if ( fi?$pcr && /^[+-]?\d+\.\d+$|^<$|^>$|^=$/ in fi$pcr ) {
        fid$pcr = fi$pcr;
    }

    # read the resp port
    if ( fi?$resp_p ) { 
        fid$resp_p =  to_count(fi$resp_p);
    }

    # Is this flow in our flow_kb already? 
    if ( fid in flow_kb ) {
        # update a kb entry

        # Check known-flow field
        if ( fi?$known ) {
            flow_kb[fid]$known = fi$known;
        }

        # Check authorized field
        if ( fi?$authorized ) {
            flow_kb[fid]$authorized = fi$authorized;
        }

        # Check suspicious field
        if ( fi?$suspicious ) {
            flow_kb[fid]$suspicious = fi$suspicious;
        }

        # Check labels field
        if ( fi?$labels ) {
            if ( token_pattern in fi$labels ) {
                local label_update = split_string(to_lower(strip(fi$labels)), token_pattern);
                for ( ue in label_update ) {
                    if ( |label_update[ue]| > 0 ) {
                        add flow_kb[fid]$labels[strip(label_update[ue])];
                    }
                }
            }
            else {
                add flow_kb[fid]$labels[to_lower(fi$labels)];
            }
        }
    }
    else {
        # create new flow kb entry 

        # New flow meta record             
        local fmeta = flow_meta();
        fmeta$labels = set();

        # Check known-flow field
        if ( fi?$known ) {
            fmeta$known = fi$known;
        }

        # Check authorized field
        if ( fi?$authorized ) {
            fmeta$authorized = fi$authorized;
        }

        # Check authorized field
        if ( fi?$suspicious ) {
            fmeta$suspicious = fi$suspicious;
        }

        # Check labels field
        if ( fi?$labels ) {
            if ( token_pattern in fi$labels ) {
                local lstring = split_string(to_lower(strip(fi$labels)), token_pattern);
                for ( ne in lstring ) {
                    if ( |lstring[ne]| > 0 ) {
                        add fmeta$labels[strip(lstring[ne])];
                    }
                }
            }
            else {
                add fmeta$labels[to_lower(fi$labels)];
            }
        }

        flow_kb[fid] = fmeta;

    }
}

# Load the label datafiles on the Manager node only
event bro_init() {
    if ( static_cidr_labels != "" ) {
        Input::add_event([$source=static_cidr_labels,
                          $reader=Input::READER_ASCII,
                          $mode=Input::REREAD,
                          $name="cidr_labels",
                          $fields=flow_labels::cidr_label_entry,
                          $ev=flow_labels::read_cidr_labels]);
    }

    if ( static_flow_labels != "" ) {
        Input::add_event([$source=static_flow_labels,
                          $reader=Input::READER_ASCII,
                          $mode=Input::REREAD,
                          $name="flow_labels",
                          $fields=flow_labels::flow_label_entry,
                          $ev=flow_labels::read_flow_labels]);
    }
}

@endif
