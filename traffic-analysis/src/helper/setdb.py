from src.helper.utils import *
from src.helper.address import * # get_ipv6_type, address_configuration_method_text
# from src.helper.utils import global_lock
# import queue
logger = logging.getLogger('IoTv6')
# task_queue = queue.Queue()

def setup_exp_db(expname, out_dir, device):
    dbcon = sqlite3.connect(f"{out_dir}/{expname}_{device}.db", timeout=5)
    return dbcon, dbcon.cursor()

def drop_tables(cur):
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dhcp_reply")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dns_response")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_mdns_response")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dhcp_solicit")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dhcp_info_requests")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dhcp_requests")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_dhcp_advertisements")
    cur.execute("DROP TRIGGER IF EXISTS prevent_duplicate_ra")
    cur.execute("DROP TRIGGER IF EXISTS update_data_trigger")
    cur.execute("DROP TRIGGER IF EXISTS update_rs_count_trigger")
    cur.execute("DROP TRIGGER IF EXISTS update_na_count_trigger")
    cur.execute("DROP TRIGGER IF EXISTS update_ns_count_trigger")
    cur.execute("DROP TABLE IF EXISTS NS")
    cur.execute("DROP TABLE IF EXISTS NA")
    cur.execute("DROP TABLE IF EXISTS RS")
    cur.execute("DROP TABLE IF EXISTS RA")
    
    cur.execute("DROP TABLE IF EXISTS DNS_Requests")
    cur.execute("DROP TABLE IF EXISTS DNS_Responses")
    cur.execute("DROP TABLE IF EXISTS MDNS_Requests")
    cur.execute("DROP TABLE IF EXISTS MDNS_Responses")
    
    cur.execute("DROP TABLE IF EXISTS DHCP_Information_Requests")
    cur.execute("DROP TABLE IF EXISTS DHCP_Solicits")
    cur.execute("DROP TABLE IF EXISTS DHCP_Requests")
    cur.execute("DROP TABLE IF EXISTS DHCP_Reply")
    cur.execute("DROP TABLE IF EXISTS DHCP_Advertisements")
    cur.execute("DROP TABLE IF EXISTS Devices")
    cur.execute("DROP TABLE IF EXISTS Data")

def create_tables(cur):

    # Creating a table for Neighbor Solicitations 
    ns_query = """
        CREATE TABLE IF NOT EXISTS NS(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL, 
            target TEXT NOT NULL, 
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            type TEXT DEFAULT 'Unknown' CHECK(type IN ('LinkLocal', 'GlobalUnicast', 'UniqueLocal', 'Unknown', 'Unspecified')) NOT NULL,
            UNIQUE(mac, target, src_ip, dest_ip)
        )
    """

    # Creating table for Neighbor Advertisements 
    na_query = """
        CREATE TABLE IF NOT EXISTS NA(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            target TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, target, src_ip, dest_ip)
        )
    """

    # Creating table to store Router Advertisements 
    # note router_addr : Is link layer address of router, to identify advertisement source this is 
    # not yet implemented in my previous analysis 
    ra_query = """
        CREATE TABLE IF NOT EXISTS RA(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            M INTEGER,
            O INTEGER, 
            A INTEGER,
            prefix TEXT, 
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            dns_resolver_ip TEXT, 
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            method TEXT NOT NULL,
            UNIQUE(mac, src_ip, dest_ip, prefix, dns_resolver_ip, M, O, A)
        )
    """

    # Creating table for router solicitation 
    rs_query = """
        CREATE TABLE IF NOT EXISTS RS(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL,
            src_ip TEXT NOT NULL, 
            dest_ip TEXT NOT NULL, 
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, src_ip, dest_ip)
        )
    """

    # Creating table for tested devices 
    devices_query = """
        CREATE TABLE IF NOT EXISTS Devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            result TEXT DEFAULT 'Skipped' CHECK (result IN ('PASSED', 'FAILED', 'SKIPPED')) NOT NULL
        )
    """

    data_query = """
        CREATE TABLE IF NOT EXISTS Data(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            version INTEGER CHECK (version IN (4, 6)) NOT NULL,
            size INTEGER DEFAULT 0 CHECK (size >= 0) NOT NULL,
            flow TEXT CHECK (flow IN ('Incoming', 'Outgoing')) NOT NULL,
            protocol TEXT CHECK (protocol IN ('UDP', 'TCP')) NOT NULL,
            type TEXT CHECK (type IN ('Global', 'Local', 'Matter')) NOT NULL,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, src_ip, dest_ip, flow, protocol, version, type)
        ) 
    """

    dns_req_query = """
        CREATE TABLE IF NOT EXISTS DNS_Requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            src_ip TEXT, 
            query_type TEXT, 
            query_name TEXT,
            tsn_id TEXT,
            version INTEGER CHECK (version IN (4, 6)),
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, src_ip, tsn_id, query_type, query_name, version)
        )
    """

    dns_res_query = """
        CREATE TABLE IF NOT EXISTS DNS_Responses(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            query_name TEXT, 
            ans_type TEXT, 
            ans_data TEXT,
            tsn_id TEXT,
            status INTEGER,
            version INTEGER CHECK (version IN (4, 6)),
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, tsn_id, query_name, ans_type, ans_data, version, status)
        )
    """
    
    mdns_req_query = """
        CREATE TABLE IF NOT EXISTS MDNS_Requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            dns_resolver_ip TEXT, 
            query_type TEXT, 
            query_name TEXT,
            tsn_id TEXT,
            version INTEGER CHECK (version IN (4, 6)),
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, dns_resolver_ip, tsn_id, query_type, query_name, version)
        )
    """

    mdns_res_query = """
        CREATE TABLE IF NOT EXISTS MDNS_Responses(
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            mac TEXT NOT NULL, 
            query_name TEXT, 
            ans_type TEXT, 
            ans_data TEXT,
            req_id INTEGER,
            status INTEGER,
            version INTEGER CHECK (version IN (4, 6)),
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            FOREIGN KEY (req_id) REFERENCES MDNS_Requests(id),
            UNIQUE(mac, req_id, query_name, ans_type, ans_data, version, status)
        )
    """

    dhcp_reply_query = """
        CREATE TABLE IF NOT EXISTS DHCP_Reply(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL, 
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            solicit_id INTEGER,
            info_id INTEGER,
            iana_ip TEXT,
            iata_ip TEXT,
            options TEXT,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            FOREIGN KEY (solicit_id) REFERENCES DHCP_Solicits(id),
            FOREIGN KEY (info_id) REFERENCES DHCP_Information_Requests(id),
            UNIQUE(mac, src_ip, dest_ip, iana_ip, iata_ip, solicit_id, options)
        )
    """

    dhcp_solicit_query = """
        CREATE TABLE IF NOT EXISTS DHCP_Solicits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            tsn_id TEXT,             
            client_duid TEXT,
            options TEXT,
            requested_options TEXT,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options)
        )
    """

    dhcp_advertise_query = """
        CREATE TABLE IF NOT EXISTS DHCP_Advertisements(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL, 
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            solicit_id INTEGER,
            server_duid TEXT,
            dns_resolver_ip TEXT, 
            iana_ip TEXT,
            iata_ip TEXT,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            FOREIGN KEY (solicit_id) REFERENCES DHCP_Solicits(id),
            UNIQUE(mac, src_ip, dest_ip, solicit_id, server_duid, dns_resolver_ip, iana_ip, iata_ip)
        )
    """

    dhcp_request_query = """
        CREATE TABLE IF NOT EXISTS DHCP_Requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            solicit_id INTEGER,
            iana_ip TEXT,
            iata_ip TEXT,
            options TEXT,
            requested_options TEXT,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            FOREIGN KEY (solicit_id) REFERENCES DHCP_Solicits(id),
            UNIQUE(mac, src_ip, dest_ip, solicit_id, iana_ip, iata_ip, options, requested_options)
        )
    """

    dhcp_info_query = """
        CREATE TABLE IF NOT EXISTS DHCP_Information_Requests(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL, 
            tsn_id TEXT,
            client_duid TEXT,
            options TEXT,
            requested_options TEXT,
            count INTEGER DEFAULT 1 CHECK (count >= 0) NOT NULL,
            UNIQUE(mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options)
        )
    """
    
    cur.execute(ns_query)
    cur.execute(na_query)
    cur.execute(rs_query)
    cur.execute(ra_query)
    cur.execute(devices_query)
    cur.execute(data_query)
    cur.execute(dns_req_query)
    cur.execute(dns_res_query)
    cur.execute(mdns_req_query)
    cur.execute(mdns_res_query)
    cur.execute(dhcp_reply_query)
    cur.execute(dhcp_solicit_query)
    cur.execute(dhcp_advertise_query)
    cur.execute(dhcp_request_query)
    cur.execute(dhcp_info_query)

    
    create_trigger_ra(cur)    
    create_trigger_rs(cur)
    create_trigger_na(cur)
    create_trigger_ns(cur)
    create_trigger_data(cur)
    create_trigger_dhcp_solicit(cur)
    create_trigger_dhcp_requests(cur)
    create_trigger_dhcp_info_requests(cur)
    create_triggers_dhcp_reply(cur)
    create_trigger_dhcp_advertisements(cur)
    create_trigger_dns_response(cur)
    create_trigger_mdns_response(cur)
    
def create_trigger_dns_response(cur):
    trg_query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dns_response
        BEFORE INSERT ON DNS_Responses
        BEGIN
            UPDATE DNS_Responses SET count = count + 1
            WHERE
                (
                    (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
                ) AND
                (
                    (tsn_id IS NOT NULL AND tsn_id = NEW.tsn_id) OR (tsn_id IS NULL AND NEW.tsn_id IS NULL)
                ) AND
                (
                    (query_name IS NOT NULL AND query_name = NEW.query_name) OR (query_name IS NULL AND NEW.query_name IS NULL)
                ) AND
                (
                    (ans_type IS NOT NULL AND ans_type = NEW.ans_type) OR (ans_type IS NULL AND NEW.ans_type IS NULL)
                ) AND
                (
                    (ans_data IS NOT NULL AND ans_data = NEW.ans_data) OR (ans_data IS NULL AND NEW.ans_data IS NULL)
                ) AND
                (
                    (version IS NOT NULL AND version = NEW.version) OR (version IS NULL AND NEW.version IS NULL)
                )AND
                (
                    (status IS NOT NULL AND status = NEW.status) OR (status IS NULL AND NEW.status IS NULL)
                );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(trg_query)

def create_trigger_mdns_response(cur):
    trg_query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_mdns_response
        BEFORE INSERT ON MDNS_Responses
        BEGIN
            UPDATE MDNS_Responses SET count = count + 1
            WHERE
                (
                    (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
                ) AND
                (
                    (req_id IS NOT NULL AND req_id = NEW.req_id) OR (req_id IS NULL AND NEW.req_id IS NULL)
                ) AND
                (
                    (query_name IS NOT NULL AND query_name = NEW.query_name) OR (query_name IS NULL AND NEW.query_name IS NULL)
                ) AND
                (
                    (ans_type IS NOT NULL AND ans_type = NEW.ans_type) OR (ans_type IS NULL AND NEW.ans_type IS NULL)
                ) AND
                (
                    (ans_data IS NOT NULL AND ans_data = NEW.ans_data) OR (ans_data IS NULL AND NEW.ans_data IS NULL)
                ) AND
                (
                    (version IS NOT NULL AND version = NEW.version) OR (version IS NULL AND NEW.version IS NULL)
                )AND
                (
                    (status IS NOT NULL AND status = NEW.status) OR (status IS NULL AND NEW.status IS NULL)
                );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(trg_query)
    
def create_trigger_na(cur):
    query = """
        CREATE TRIGGER IF NOT EXISTS update_na_count_trigger
        BEFORE INSERT ON NA
        BEGIN
            UPDATE NA SET count = count + 1
            WHERE
                (mac = NEW.mac) AND
                (target = NEW.target) AND
                (src_ip = NEW.src_ip) AND
                (dest_ip = NEW.dest_ip);
        END;
    """
    cur.executescript(query)
    
def create_trigger_rs(cur):
    query = """
        CREATE TRIGGER IF NOT EXISTS update_rs_count_trigger
        BEFORE INSERT ON RS
        BEGIN
            UPDATE RS SET count = count + 1
            WHERE
                (mac = NEW.mac) AND
                (src_ip = NEW.src_ip) AND
                (dest_ip = NEW.dest_ip);
        END;
    """
    cur.executescript(query)
    
def create_trigger_ns(cur):
    query = """
        CREATE TRIGGER IF NOT EXISTS update_ns_count_trigger
        BEFORE INSERT ON NS
        BEGIN
            UPDATE NS SET count = count + 1
            WHERE
                (mac = NEW.mac) AND
                (target = NEW.target) AND
                (src_ip = NEW.src_ip) AND
                (dest_ip = NEW.dest_ip);
        END;
    """
    cur.executescript(query)
    
def create_trigger_ra(cur):
    
    trg_query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_ra
        BEFORE INSERT ON RA
        BEGIN
            UPDATE RA SET count = count + 1
            WHERE
                (
                    (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
                ) AND
                (
                    (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
                ) AND
                (
                    (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
                ) AND
                (
                    (dns_resolver_ip IS NOT NULL AND dns_resolver_ip = NEW.dns_resolver_ip) OR (dns_resolver_ip IS NULL AND NEW.dns_resolver_ip IS NULL)
                ) AND
                (
                    (prefix IS NOT NULL AND prefix = NEW.prefix) OR (prefix IS NULL AND NEW.prefix IS NULL)
                );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(trg_query)
    
def create_triggers_dhcp_reply(cur):
    
    trg_query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_reply
        BEFORE INSERT ON DHCP_Reply
        BEGIN
            UPDATE DHCP_Reply SET count = count + 1
            WHERE 
                (
                    (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
                ) AND
                (
                    (options IS NOT NULL AND options = NEW.options) OR (options IS NULL AND NEW.options IS NULL)
                ) AND
                (
                    (iana_ip IS NOT NULL AND iana_ip = NEW.iana_ip) OR (iana_ip IS NULL AND NEW.iana_ip IS NULL)
                ) AND
                (
                    (iata_ip IS NOT NULL AND iata_ip = NEW.iata_ip) OR (iata_ip IS NULL AND NEW.iata_ip IS NULL)
                ) AND
                (
                    (solicit_id IS NOT NULL AND solicit_id = NEW.solicit_id) OR (solicit_id IS NULL AND NEW.solicit_id IS NULL)
                ) AND
                (
                    (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
                ) AND
                (
                    (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
                );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(trg_query)
    
def create_trigger_dhcp_solicit(cur):
    
    query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_solicit
        BEFORE INSERT ON DHCP_Solicits
        BEGIN
            UPDATE DHCP_Solicits SET count = count + 1
            WHERE (
                (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
            ) AND
            (
                (options IS NOT NULL AND options = NEW.options) OR (options IS NULL AND NEW.options IS NULL)
            ) AND
            (
                (requested_options IS NOT NULL AND requested_options = NEW.requested_options) OR (requested_options IS NULL AND NEW.requested_options IS NULL)
            ) AND
            (
                (tsn_id IS NOT NULL AND tsn_id = NEW.tsn_id) OR (tsn_id IS NULL AND NEW.tsn_id IS NULL)
            ) AND
            (
                (client_duid IS NOT NULL AND client_duid = NEW.client_duid) OR (client_duid IS NULL AND NEW.client_duid IS NULL)
            ) AND
            (
                (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
            ) AND
            (
                (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
            );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(query)

def create_trigger_dhcp_advertisements(cur):
    query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_advertisements
        BEFORE INSERT ON DHCP_Advertisements
        BEGIN
            UPDATE DHCP_Advertisements SET count = count + 1
            WHERE (
                (mac IS NOT NULL AND mac = NEW.mac) 
            ) AND
            (
                (iana_ip IS NOT NULL AND iana_ip = NEW.iana_ip) OR (iana_ip IS NULL AND NEW.iana_ip IS NULL)
            ) AND
            (
                (iata_ip IS NOT NULL AND iata_ip = NEW.iata_ip) OR (iata_ip IS NULL AND NEW.iata_ip IS NULL)
            ) AND
            (
                (solicit_id IS NOT NULL AND solicit_id = NEW.solicit_id) OR (solicit_id IS NULL AND NEW.solicit_id IS NULL)
            ) AND
            (
                (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
            ) AND
            (
                (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
            )AND
            (
                (dns_resolver_ip = NEW.dns_resolver_ip) OR (dns_resolver_ip IS NULL AND NEW.dns_resolver_ip IS NULL)
            )AND
            (
                (server_duid IS NOT NULL AND server_duid = NEW.server_duid) OR (server_duid IS NULL AND NEW.server_duid IS NULL)
            );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    # query = """
    #     CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_advertisements
    #     BEFORE INSERT ON DHCP_Advertisements
    #     WHEN EXISTS (
    #         SELECT 1
    #         FROM DHCP_Advertisements
    #         WHERE (
    #             (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
    #         ) AND
    #         (
    #             (iana_ip IS NOT NULL AND iana_ip = NEW.iana_ip) OR (iana_ip IS NULL AND NEW.iana_ip IS NULL)
    #         ) AND
    #         (
    #             (iata_ip IS NOT NULL AND iata_ip = NEW.iata_ip) OR (iata_ip IS NULL AND NEW.iata_ip IS NULL)
    #         ) AND
    #         (
    #             (solicit_id IS NOT NULL AND solicit_id = NEW.solicit_id) OR (solicit_id IS NULL AND NEW.solicit_id IS NULL)
    #         ) AND
    #         (
    #             (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
    #         ) AND
    #         (
    #             (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
    #         )AND
    #         (
    #             (dns_resolver_ip IS NOT NULL AND dns_resolver_ip = NEW.dns_resolver_ip) OR (dns_resolver_ip IS NULL AND NEW.dns_resolver_ip IS NULL)
    #         )AND
    #         (
    #             (server_duid IS NOT NULL AND server_duid = NEW.server_duid) OR (server_duid IS NULL AND NEW.server_duid IS NULL)
    #         )
    #     )
    #     BEGIN
    #         SELECT RAISE(ABORT, 'Duplicate record not allowed');
    #     END;
    # """
    cur.executescript(query)

def create_trigger_dhcp_requests(cur):
    
    query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_requests
        BEFORE INSERT ON DHCP_Requests
        BEGIN
            UPDATE DHCP_Requests SET count = count + 1
            WHERE (
                (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
            ) AND
            (
                (options IS NOT NULL AND options = NEW.options) OR (options IS NULL AND NEW.options IS NULL)
            ) AND
            (
                (requested_options IS NOT NULL AND requested_options = NEW.requested_options) OR (requested_options IS NULL AND NEW.requested_options IS NULL)
            ) AND
            (
                (iana_ip IS NOT NULL AND iana_ip = NEW.iana_ip) OR (iana_ip IS NULL AND NEW.iana_ip IS NULL)
            ) AND
            (
                (iata_ip IS NOT NULL AND iata_ip = NEW.iata_ip) OR (iata_ip IS NULL AND NEW.iata_ip IS NULL)
            ) AND
            (
                (solicit_id IS NOT NULL AND solicit_id = NEW.solicit_id) OR (solicit_id IS NULL AND NEW.solicit_id IS NULL)
            ) AND
            (
                (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
            ) AND
            (
                (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
            );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(query)

def create_trigger_dhcp_info_requests(cur):
    
    query = """
        CREATE TRIGGER IF NOT EXISTS prevent_duplicate_dhcp_info_requests
        BEFORE INSERT ON DHCP_Information_Requests
        BEGIN
            UPDATE DHCP_Information_Requests SET count = count + 1
            WHERE (
                (mac IS NOT NULL AND mac = NEW.mac) OR (mac IS NULL AND NEW.mac IS NULL)
            ) AND
            (
                (options IS NOT NULL AND options = NEW.options) OR (options IS NULL AND NEW.options IS NULL)
            ) AND
            (
                (requested_options IS NOT NULL AND requested_options = NEW.requested_options) OR (requested_options IS NULL AND NEW.requested_options IS NULL)
            ) AND
            (
                (tsn_id IS NOT NULL AND tsn_id = NEW.tsn_id) OR (tsn_id IS NULL AND NEW.tsn_id IS NULL)
            ) AND
            (
                (client_duid IS NOT NULL AND client_duid = NEW.client_duid) OR (client_duid IS NULL AND NEW.client_duid IS NULL)
            ) AND
            (
                (src_ip IS NOT NULL AND src_ip = NEW.src_ip) OR (src_ip IS NULL AND NEW.src_ip IS NULL)
            ) AND
            (
                (dest_ip IS NOT NULL AND dest_ip = NEW.dest_ip) OR (dest_ip IS NULL AND NEW.dest_ip IS NULL)
            );
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(query)
    
def create_trigger_data(cur):
    
    query = """
        CREATE TRIGGER IF NOT EXISTS update_data_trigger 
        BEFORE INSERT ON Data
        BEGIN
            UPDATE Data
            SET size = size + NEW.size, count = count + 1
            WHERE mac = NEW.mac 
                AND src_ip = NEW.src_ip 
                AND dest_ip = NEW.dest_ip 
                AND flow = NEW.flow 
                AND protocol = NEW.protocol 
                AND type = NEW.type
                AND version = NEW.version;
            SELECT CASE
                WHEN (SELECT changes() > 0) THEN RAISE(IGNORE)
            END;
        END;
    """
    cur.executescript(query)

# def db_writer(q, expname, out_dir):
#     conn, cur = setup_exp_db(expname, out_dir)
#     while True:
#         data = q.get()  # Blocks until data is available
#         if data is None:  # A None entry in the queue is used to signal the thread to end
#             break
#         db_query, values = data
#         # Process and insert data into the database
#         write_to_db(cur, db_query, values)
#         conn.commit()

#     conn.close()


def write_to_db(cur, db_query, values, attempt=1):
    try:
        # with global_lock:
        cur.execute(db_query, (values))
    except sqlite3.IntegrityError as e:
        logger.error(f"Integrity Error: {e} | {db_query}")
    except sqlite3.OperationalError as e:
        if str(e) == "database is locked":
            if attempt <= 5:  # retry up to 5 times
                time.sleep(1)  # wait for 1 second before retrying
                logger.warning(f"Database is locked, retrying {attempt} time(s)")
                write_to_db(cur, db_query, values, attempt+1)
            else:
                logger.error(f"Database is locked, unable to write to database after {attempt} attempts")
                raise

def insert_ns(cur, mac, target, src_ip, dest_ip, type):
    type = get_ipv6_type(target)
    if type == "Unknown":
        logger.warning(f"{mac}: NS message {target=} is an unknown invalid IPv6 address")
    # if type == 1:
    #     logger.error('invalid address, not able to insert ns')
    insert_query = """
        INSERT OR IGNORE INTO NS (mac, target, src_ip, dest_ip, type)
        VALUES (?, ?, ?, ?, ?);
    """
    # task_queue.put((insert_query, (mac, target, src_ip, dest_ip, type)))
    write_to_db(cur, insert_query, (mac, target, src_ip, dest_ip, type))
    # cur.execute(insert_query, (mac, target, src_ip, dest_ip, type))

def insert_na(cur, mac, src_ip, dest_ip, target):
    insert_query = """
        INSERT OR IGNORE INTO NA (mac, target, src_ip, dest_ip)
        VALUES (?, ?, ?, ?);
    """
    # task_queue.put((insert_query, (mac, target, src_ip, dest_ip)))
    write_to_db(cur, insert_query, (mac, target, src_ip, dest_ip))
    # cur.execute(insert_query, (mac, target, src_ip, dest_ip))

def insert_rs(cur, mac, src_ip, dest_ip):
    insert_query = """
        INSERT OR IGNORE INTO RS (mac, src_ip, dest_ip)
        VALUES (?, ?, ?);
    """
    # task_queue.put((insert_query, (mac, src_ip, dest_ip)))
    write_to_db(cur, insert_query, (mac, src_ip, dest_ip))
    # cur.execute(insert_query, (mac, src_ip, dest_ip))

def insert_ra(cur, mac, m, o, a, prefix, dns_svr_list, src_ip, dest_ip):
    method = address_configuration_method_text(m, o, a)
    
    for dns_resolver_ip in dns_svr_list:
        insert_query = """
            INSERT OR IGNORE INTO RA (mac, src_ip, dest_ip, M, O, A, prefix, dns_resolver_ip, method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        # logger.debug(f"RA Insert {mac} {src_ip} {dest_ip} {m} {o} {a} {prefix} {dns_resolver_ip}, {method}")
        # task_queue.put((insert_query, (mac, src_ip, dest_ip, m, o, a, prefix, dns_resolver_ip, method)))
        write_to_db(cur, insert_query, (mac, src_ip, dest_ip, m, o, a, prefix, dns_resolver_ip, method))
        # cur.execute(insert_query, (mac, src_ip, dest_ip, m, o, a, prefix, dns_resolver_ip, method))

def insert_data(cur, mac, src_ip, dest_ip, flow, protocol, version, size, type):
    insert_query = """
        INSERT OR IGNORE INTO Data (mac, src_ip, dest_ip, flow, protocol, version, size, type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """
    # task_queue.put((insert_query, (mac, src_ip, dest_ip, flow, protocol, version, size)))
    write_to_db(cur, insert_query, (mac, src_ip, dest_ip, flow, protocol, version, size, type))
    # cur.execute(insert_query, (mac, src_ip, dest_ip, flow, protocol, version, size))
        
def insert_devices(cur, mac, name, category, result):
    insert_query = """
        INSERT OR IGNORE INTO Devices(mac, name, category, result)
        VALUES (?, ?, ?, ?);
    """
    # task_queue.put((insert_query, (mac, name, category, result)))
    write_to_db(cur, insert_query, (mac, name, category, result))
    # cur.execute(insert_query, (mac, name, category, result))

def insert_dns_request(cur, mac, query_name, query_type, src_ip, tsn_id, version):  
    dns_req_query = """
            INSERT OR IGNORE INTO DNS_Requests(mac, src_ip, query_type, query_name, tsn_id, version)
            VALUES (?, ?, ?, ?, ?, ?)
        """
    # task_queue.put((dns_req_query, (mac, dns_resolver_ip, query_type, query_name, None, version)))
    write_to_db(cur, dns_req_query, (mac,  src_ip, query_type, query_name, tsn_id, version))
    # cur.execute(dns_req_query, (mac, dns_resolver_ip, query_type, query_name, tsn_id, version))
    # logger.debug(f"DNS Request Insert {mac=} {query_name=} {query_type=} {dns_resolver_ip=} {tsn_id=} {version=}")

def insert_dns_response(cur, mac, qname, aname, atype, adata, tsn_id, status, version):

    # TODO Performance issue 
    # # Search for all the corresponding queries from DNS Requests for this response. 
    # dns_req_query_select = """
    #     SELECT id
    #     FROM DNS_Requests
    #     WHERE tsn_id = ? AND query_name = ? 
    # """ # 
    # cur.execute(dns_req_query_select, (tsn_id, qname))

    # req_ids = []
    # req_q_result = cur.fetchall()
    # for item in req_q_result:
    #     req_ids.append(item[0])
        
    # if len(req_ids) == 0:
    #     logger.debug(f"No DNS Request found for {mac} {qname} {tsn_id}")
    #     req_ids.append(None)
    # req_ids = [None]
    # for req_id in req_ids:
    dns_res_query = """
        INSERT OR IGNORE INTO DNS_Responses(mac, query_name, ans_type, ans_data, tsn_id, status, version)
        VALUES(?, ?, ?, ?, ?, ?, ?)
    """
    # task_queue.put((dns_res_query, (mac, aname, atype, adata, None, status, version)))
    write_to_db(cur, dns_res_query, (mac, qname, atype, adata, tsn_id, status, version))
    # cur.execute(dns_res_query, (mac, qname, atype, adata, id, status, version))
    # logger.debug(f"DNS Response Insert {mac=} {qname=} {aname=} {atype=} {adata=} {tsn_id=} {status=} {version=}")

def insert_mdns_request(cur, mac, query_name, query_type, dns_resolver_ip, tsn_id, version):  
    mdns_req_query = """
            INSERT OR IGNORE INTO MDNS_Requests(mac, dns_resolver_ip, query_type, query_name, tsn_id, version)
            VALUES (?, ?, ?, ?, ?, ?)
        """
    # task_queue.put((mdns_req_query, (mac, dns_resolver_ip, query_type, query_name, None, version)))
    write_to_db(cur, mdns_req_query, (mac, dns_resolver_ip, query_type, query_name, tsn_id, version))
    # cur.execute(mdns_req_query, (mac, dns_resolver_ip, query_type, query_name, tsn_id, version))

def insert_mdns_response(cur, mac, qname, aname, atype, adata, tsn_id, status, version):

    # # Search for all the corresponding queries from DNS Requests for this response. 
    # mdns_req_query = """
    #     SELECT id
    #     FROM MDNS_Requests
    #     WHERE tsn_id = ? AND query_name = ? 
    # """
    # cur.execute(mdns_req_query, (tsn_id, aname))

    # req_ids = []
    # req_q_result = cur.fetchall()
    # for item in req_q_result:
    #     req_ids.append(item[0])
        
    # if len(req_ids) == 0:
    #     req_ids.append(None)
        
    # for id in req_ids:
    mdns_res_query = """
        INSERT OR IGNORE INTO MDNS_Responses(mac, query_name, ans_type, ans_data, req_id, status, version)
        VALUES(?, ?, ?, ?, ?, ?, ?)
    """
    # task_queue.put((mdns_res_query, (mac, aname, atype, adata, None, status, version)))
    write_to_db(cur, mdns_res_query, (mac, aname, atype, adata, None, status, version))
    # cur.execute(mdns_res_query, (mac, aname, atype, adata, id, status, version))
    # logger.debug(f"MDNS Response Insert {mac=} {aname=} {atype=} {adata=} {status=} {version=}")

def insert_dhcp_solicit(cur, mac, src_ip, dest_ip, tsn_id, duid, options, requested_options):
    query = """
        INSERT OR IGNORE INTO DHCP_Solicits(mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options)
        VALUES(?, ?, ?, ?, ?, ?, ?)
    """
    if options:
        options = ';'.join(options)
    if requested_options:
        requested_options = ';'.join(requested_options)
    # task_queue.put((query, (mac, src_ip, dest_ip, tsn_id, duid, options, requested_options)))
    write_to_db(cur, query, (mac, src_ip, dest_ip, tsn_id, duid, options, requested_options))
    # cur.execute(query, (mac, src_ip, dest_ip, tsn_id, duid, options, requested_options))

def insert_dhcp_info_request(cur, mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options):
    query = """
        INSERT OR IGNORE INTO DHCP_Information_Requests(mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options)
        VALUES(?, ?, ?, ?, ?, ?, ?)
    """
    if options:
        options = ';'.join(options)
    if requested_options:
        requested_options = ';'.join(requested_options)
    # task_queue.put((query, (mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options)))
    write_to_db(cur, query, (mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options))
    # cur.execute(query, (mac, src_ip, dest_ip, tsn_id, client_duid, options, requested_options))

def insert_dhcp_advertisememts(cur, mac, src_ip, dest_ip, tsn_id, server_duid, dns_resolver_ips, iana_ips, iata_ips):
    
    solicit_ids = [] 

    # get_solicit_query = "SELECT id FROM DHCP_Solicits WHERE tsn_id = ?"
    # cur.execute(get_solicit_query, (tsn_id,))  
    # solicit_id_result = cur.fetchone()
    # solicit_id = solicit_id_result[0] if solicit_id_result else None
    solicit_ids = None
    if not dns_resolver_ips or len(dns_resolver_ips) == 0:
        iata_ips = None
    else:
        logger.debug(f"{mac}: DHCP Advertisement DNS Resolver IPs: {dns_resolver_ips}")

    if not iata_ips or len(iata_ips) == 0:
        iata_ips = None
    else:
        iata_ips = ';'.join(iata_ips)

    if not iana_ips or len(iana_ips) == 0:
        iana_ips = None
    else:
        iana_ips = ';'.join(iana_ips)
        
    # if not solicit_ids or len(solicit_ids) == 0:
    #     solicit_ids = None
    # else:
    #     solicit_ids = ';'.join(solicit_ids)
    # solicit_id = None
    
    # for iata_ip in iata_ips:
    #     for iana_ip in iana_ips:
    #         for solicit_id in solicit_ids:
    adv_insert_query = """
        INSERT INTO DHCP_Advertisements(mac, src_ip, dest_ip, solicit_id, server_duid, dns_resolver_ip, iata_ip, iana_ip)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    """
    # task_queue.put((adv_insert_query, (mac, src_ip, dest_ip, solicit_id, server_duid, dns, iata_ip, iana_ip)))
    write_to_db(cur, adv_insert_query, (mac, src_ip, dest_ip, solicit_ids, server_duid, None, iata_ips, iana_ips))
    # cur.execute(adv_insert_query, (mac, src_ip, dest_ip, solicit_id, server_duid, dns, iata_ip, iana_ip))


def insert_dhcp_request(cur, mac, src_ip, dest_ip, tsn_id, iana_ip, iata_ip, options, requested_options):

    # get_solicit_query = "SELECT id FROM DHCP_Solicits WHERE tsn_id = ?"
    # cur.execute(get_solicit_query, (tsn_id,))  
    # solicit_id_result = cur.fetchone()
    # solicit_id = solicit_id_result[0] if solicit_id_result else None
    solicit_id = None
    req_insert_query = """
        INSERT INTO DHCP_Requests(mac, src_ip, dest_ip, solicit_id, iana_ip, iata_ip, options, requested_options)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    """
    if options:
        options = ';'.join(options)
    if requested_options:
        requested_options = ';'.join(requested_options)
    # task_queue.put((req_insert_query, (mac, src_ip, dest_ip, solicit_id, iana_ip, iata_ip, options, requested_options)))
    write_to_db(cur, req_insert_query, (mac, src_ip, dest_ip, solicit_id, iana_ip, iata_ip, options, requested_options))
    # cur.execute(req_insert_query, (mac, src_ip, dest_ip, solicit_id, iana_ip, iata_ip, options, requested_options))


def insert_dhcp_reply(cur, mac, iana_ips, iata_ips, tsn_id, src_ip, dest_ip, options):
    
    # get_solicit_query = "SELECT id FROM DHCP_Solicits WHERE tsn_id = ?"
    # cur.execute(get_solicit_query, (tsn_id,))  
    # solicit_id_result = cur.fetchone()
    # solicit_id = solicit_id_result[0] if solicit_id_result else None
    solicit_id = None
    # get_info_query = "SELECT id FROM DHCP_Information_Requests WHERE tsn_id = ?"
    # cur.execute(get_info_query, (tsn_id,))  
    # info_id_result = cur.fetchone()
    # info_id = info_id_result[0] if info_id_result else None
    info_id = None
    if not iata_ips or len(iata_ips) == 0:
        iata_ips = None
    else:
        iata_ips = ';'.join(iata_ips)

    if not iana_ips or len(iana_ips) == 0:
        iana_ips = None
    else:
        iana_ips = ';'.join(iana_ips)
    reply_insert_query = """
        INSERT INTO DHCP_Reply(mac, src_ip, dest_ip, solicit_id, info_id, iana_ip, iata_ip, options)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
    """
    if options:
        options = ';'.join(options)
    # task_queue.put((reply_insert_query, (mac, src_ip, dest_ip, solicit_id, info_id, iana_ip, iata_ip, options)))
    write_to_db(cur, reply_insert_query, (mac, src_ip, dest_ip, solicit_id, info_id, iana_ips, iata_ips, options))
    # cur.execute(reply_insert_query, (mac, src_ip, dest_ip, solicit_id, info_id, iana_ip, iata_ip, options))

        