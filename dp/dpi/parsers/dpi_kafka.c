#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define    PRODUCE                  0
#define    FETCH                    1
#define    LIST_OFFSETS             2
#define    METADATA                 3
#define    LEADER_AND_ISR           4
#define    STOP_REPLICA             5
#define    UPDATE_METADATA_KEY      6
#define    CONTROLLED_SHUTDOWN_KEY  7
#define    OFFSET_COMMIT            8
#define    OFFSET_FETCH             9
#define    GROUP_COORDINATOR        10
#define    JOIN_GROUP               11
#define    HEARTBEAT                12
#define    LEAVE_GROUP              13
#define    SYNC_GROUP               14
#define    DESCRIBE_GROUPS          15
#define    LIST_GROUPS              16

#define     MAX_TOPIC_LEN           256
#define     MAX_TOPIC_NUM           256
#define     MAX_PARTITION_NUM       256
#define     MAX_KAFKA_PACKET       (1024*10000)

#define     MAX_TOPIC_PARSE         8
#define     MAX_PARTI_PARSE         16

typedef struct kafka_wing_ {
    uint32_t seq;
    uint32_t corr_id[4];
    int left;
    uint8_t  corr_id_cnt;
} kafka_wing_t;

typedef struct kafka_data_ {
    kafka_wing_t client, server;
    uint32_t topic_len;
    uint8_t valid_request:1,
            checked_request:1;
} kafka_data_t;

//get string from package, two bytes string len followed by string
//return false: >0  --- bytes parsed 
//              0  --- not enough data
//              -1 --- error data
static int get_short_string_len(uint8_t *ptr, int * pleft)
{
    int i;

    if (*pleft < 2 ) return 0;

    uint16_t string_len  = GET_BIG_INT16(ptr);

    if (string_len > MAX_TOPIC_LEN) {
        return -1;
    } 
    if (*pleft < (string_len + 2)) {
        return 0;
    } 
    ptr += 2; *pleft -= 2;
    for (i = 0; i < string_len; i++) {
        if (!isprint(*ptr)) {
            return -1;
        }
        ptr ++;
    }
    *pleft -= string_len;

    return string_len + 2;
}

//return false: >0  --- bytes parsed 
//              0  --- not enough data
//              -1 --- error data
static int get_count(uint8_t *ptr, int * pleft, int limit)
{
    if (*pleft < 4 ) return 0;

    uint32_t count = GET_BIG_INT32(ptr);

    if (count > limit) {
        return -1;
    } else {
        return count;
    }
}

static int get_bytes(uint8_t *ptr, int * pleft)
{
    if (*pleft < 4 ) return 0;

    return GET_BIG_INT32(ptr);
}


static int check_produce_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int   str_len, i,j;
    int   topic_count  = 0 ;
    int   parti_count  = 0 ;
    int   size_bytes   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka produce\n");

    str_len = get_short_string_len(ptr, pleft); //pleft will be substrated inside
    ptr += str_len; size_left -= str_len;
    int client_id_len = str_len-2;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka produce client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    ptr += 2; *pleft -= 2; size_left -= 2;//requiredAcks
    ptr += 4; *pleft -= 4; size_left -= 4;//ackTimeoutMs

    topic_count = get_count(ptr, pleft,MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }

    if (client_id_len == 0 && topic_count == 0 && size_left > 0) {
        DEBUG_LOG(DBG_PARSER, p, "Kafka all field 0\n");
        return -1;
    }
    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);//pleft will be substrated inside
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka produce topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;

        parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//partition count
        if (parti_count < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
            return size_left < 0 ? -1 : parti_count;
        }
        DEBUG_LOG(DBG_PARSER, p, "Kafka parti_count: %d\n",parti_count);
        for (j=0; j < parti_count; j++) {
            ptr += 4; *pleft -= 4; size_left -= 4;//partition id

            size_bytes = get_bytes(ptr, pleft);
            ptr += 4; *pleft -= 4; size_left -= 4;//byte-length of serialized messages
            ptr += size_bytes; *pleft -= size_bytes; size_left -= size_bytes;//byte-length of serialized messages
            DEBUG_LOG(DBG_PARSER, p, "Kafka size_bytes=%d pleft=%d\n", size_bytes, *pleft);
            if (size_left < 0 ) {
                DEBUG_LOG(DBG_PARSER, p, "Not Kafka produce partition\n");
                return -1;
            }
            if (j > MAX_PARTI_PARSE) {
                data->valid_request = true;
                data->checked_request = true;
                return 1;
            }
        }
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (parti_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_fetch_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, uint16_t version_id, int size_left)
{
    int   str_len, i, j;
    int   topic_count;
    int   parti_count;

    DEBUG_LOG(DBG_PARSER, p, "Kafka fetch\n");

    str_len = get_short_string_len(ptr, pleft);//pleft will be substrated inside
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    ptr += 4; *pleft -= 4; size_left -= 4;//replicaId
    ptr += 4; *pleft -= 4; size_left -= 4;//maxWait
    ptr += 4; *pleft -= 4; size_left -= 4;//minBytes
    if (version_id >= 3) {
        ptr += 4; *pleft -= 4; size_left -= 4;//maxBytes
    }

    topic_count = get_count(ptr, pleft,MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }

    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);//pleft will be substrated inside
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;

        parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//partition count
        if (parti_count < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
            return size_left < 0 ? -1 : parti_count;
        }
        for (j=0; j < parti_count; j++) {
            ptr += 4; *pleft -= 4; size_left -= 4;//partition id
            ptr += 8; *pleft -= 8; size_left -= 8;//offset
            ptr += 4; *pleft -= 4; size_left -= 4;//fetch size
            if (size_left < 0 ) {
                DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch partition\n");
                return -1;
            }
            if (j > MAX_PARTI_PARSE) {
                data->valid_request = true;
                data->checked_request = true;
                return 1;
            }
        }
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (topic_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_list_offsets_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int   str_len, i, j ;
    int   topic_count   ;
    int   parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka list offsets\n");

    str_len = get_short_string_len(ptr, pleft);//pleft will be substrated inside
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    ptr += 4; *pleft -= 4; size_left -= 4;//replicaId

    topic_count = get_count(ptr, pleft, MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }
    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);//pleft will be substrated inside
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka list offsets topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;

        parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//partition count
        if (parti_count < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
            return size_left < 0 ? -1 : parti_count;
        }
        for (j=0; j < parti_count; j++) {
            ptr += 4; *pleft -= 4; size_left -= 4;//partition id
            ptr += 8; *pleft -= 8; size_left -= 8;//time
            ptr += 4; *pleft -= 4; size_left -= 4;//maxNumOffsets
            if (size_left < 0 ) {
                DEBUG_LOG(DBG_PARSER, p, "Not Kafka list offsets partition\n");
                return -1;
            }
            if (j > MAX_PARTI_PARSE) {
                data->valid_request = true;
                data->checked_request = true;
                return 1;
            }
        }
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (topic_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}
static int check_metadata_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int   str_len, i ;
    int   topic_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka metadata\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    topic_count = get_count(ptr, pleft,MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }
    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka metadata topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (topic_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_leader_and_isr_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int        str_len, i ;
    int   parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka leader and isr\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    ptr += 4; *pleft -= 4; size_left -= 4;//controller id
    ptr += 4; *pleft -= 4; size_left -= 4;//controller epoch

    parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//partition count
    if (parti_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
        return size_left < 0 ? -1 : parti_count;
    }
    for (i=0; i < parti_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka metadata topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;
        ptr += 4; *pleft -= 4; size_left -= 4;//partition

        //the following is parsing object PartitionStateInfo
        ptr += 4; *pleft -= 4; size_left -= 4;//controllerEpoch
        ptr += 4; *pleft -= 4; size_left -= 4;//leader
        ptr += 4; *pleft -= 4; size_left -= 4;//leaderEpoch
        int isrSize = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//isrSize
        if (isrSize <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : isrSize;
        }
        ptr += 4*isrSize; *pleft -= 4*isrSize; size_left -= 4*isrSize;//isr = for(i <- 0 until isrSize) yield
        ptr += 4; *pleft -= 4; size_left -= 4;//zkVersion
        int replicationFactor = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//replicationFactor
        if (replicationFactor <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : replicationFactor;
        }
        //replicas = for(i <- 0 until replicationFactor) yield
        ptr += 4*replicationFactor; *pleft -= 4*replicationFactor; size_left -= 4*replicationFactor;
        //end of PartitionStateInfo
        if (i > MAX_PARTI_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (parti_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_replica_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int        str_len, i ;
    int   parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka stop replica\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 
    ptr += 4; *pleft -= 4; size_left -= 4; //controller id
    ptr += 4; *pleft -= 4; size_left -= 4; //controller epoch
    ptr += 1; *pleft -= 1; size_left -= 1; //deleter partition

    parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//partition count
    if (parti_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
        return size_left < 0 ? -1 : parti_count;
    }

    for (i=0; i < parti_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;
        ptr += 4; *pleft -= 4; size_left -= 4; //partition id
        if (i > MAX_PARTI_PARSE) {
            data->checked_request = true;
            return 1;
        }
    }

    if (parti_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_update_metadata_key_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int        str_len, i ;
    int        parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka update metadata key\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka update metadata client id\n");
        return size_left < 0 ? -1 : str_len;
    } 
    ptr += 4; *pleft -= 4; size_left -= 4; //controller id
    ptr += 4; *pleft -= 4; size_left -= 4; //controller epoch

    parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//partition count
    if (parti_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
        return size_left < 0 ? -1 : parti_count;
    }

    DEBUG_LOG(DBG_PARSER, p, "Kafka parti_count: %d\n",parti_count);
    for (i=0; i < parti_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : str_len;
        }  
        ptr += str_len;

        ptr += 4; *pleft -= 4; size_left -= 4; //partition id
        
        //the following is parsing object PartitionStateInfo
        ptr += 4; *pleft -= 4; size_left -= 4;//controllerEpoch
        ptr += 4; *pleft -= 4; size_left -= 4;//leader
        ptr += 4; *pleft -= 4; size_left -= 4;//leaderEpoch
        int isrSize = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//isrSize
        if (isrSize < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : isrSize;
        }  
        ptr += 4*isrSize; *pleft -= 4*isrSize; size_left -= 4*isrSize;//isr = for(i <- 0 until isrSize) yield
        ptr += 4; *pleft -= 4; size_left -= 4;//zkVersion
        int replicationFactor = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//replicationFactor
        if (replicationFactor <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not check replica topic\n");
            return size_left < 0 ? -1 : replicationFactor;
        }  
        //replicas = for(i <- 0 until replicationFactor) yield
        ptr += 4*replicationFactor; *pleft -= 4*replicationFactor; size_left -= 4*replicationFactor;
        if (i > MAX_PARTI_PARSE) {
            data->checked_request = true;
            return 1;
        }
    }

    data->checked_request = true;
    return 1;
}

static int check_offset_commit_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, uint16_t version_id, int *pleft, int size_left)
{
    int   str_len, i, j;
    int   topic_count   ;
    int   parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka offset commit\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka update metadata client id\n");
        return size_left < 0 ? -1 : str_len;
    } 
    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka update metadata client id\n");
        return size_left < 0 ? -1 : str_len;
    } 
    DEBUG_LOG(DBG_PARSER, p, "Kafka group id: %s\n",(char*)(ptr+2));

    if (version_id >= 2 ) {
        ptr += 8; *pleft -= 8; size_left -= 8;//retention time
    } else if (version_id >= 1 ) {
        ptr += 4; *pleft -= 4; size_left -= 4;//group generation id
    }

    topic_count = get_count(ptr, pleft,MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }
    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka metadata topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;

        parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//partition count
        if (parti_count < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
            return size_left < 0 ? -1 : parti_count;
        }
        for (j=0; j < parti_count; j++) {
            ptr += 4; *pleft -= 4; size_left -= 4;//partition
            ptr += 8; *pleft -= 8; size_left -= 4;//offset
            if (version_id == 1) {
                ptr += 8; *pleft -= 8; size_left -= 8;//timestamp
            }

            str_len = get_short_string_len(ptr, pleft);
            size_left -= str_len;
            if (str_len <= 0 || size_left < 0) {
                DEBUG_LOG(DBG_PARSER, p, "Not Kafka metadata topic\n");
                return size_left < 0 ? -1 : str_len;
            } 
            ptr += str_len;
            if (j > MAX_PARTI_PARSE) {
                data->valid_request = true;
                data->checked_request = true;
                return 1;
            }
        }
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (topic_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_offset_fetch_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int   str_len, i,j ;
    int   topic_count   ;
    int   parti_count   ;

    DEBUG_LOG(DBG_PARSER, p, "Kafka offset fetch\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka offset fetch client id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka offset fetch group id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    topic_count = get_count(ptr, pleft,MAX_TOPIC_NUM);
    ptr += 4; *pleft -= 4; size_left -= 4;//topic count
    if (topic_count < 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka topic_count: %d,size_left:%d\n",topic_count, size_left);
        return size_left < 0 ? -1 : topic_count;
    }
    for (i=0; i < topic_count; i++) {
        //topic
        str_len = get_short_string_len(ptr, pleft);
        size_left -= str_len;
        if (str_len <= 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka metadata topic\n");
            return size_left < 0 ? -1 : str_len;
        } 
        ptr += str_len;

        parti_count = get_count(ptr, pleft,MAX_PARTITION_NUM);
        ptr += 4; *pleft -= 4; size_left -= 4;//partition count
        if (parti_count < 0 || size_left < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Not Kafka parti_count: %d\n",parti_count);
            return size_left < 0 ? -1 : parti_count;
        }
        for (j=0; j < parti_count; j++) {
            ptr += 4; *pleft -= 4; size_left -= 4;//partition
        }
        if (i > MAX_TOPIC_PARSE) {
            data->valid_request = true;
            data->checked_request = true;
            return 1;
        }
    }

    if (topic_count > 0 && *pleft == 0) {
        data->valid_request = true;
    }
    data->checked_request = true;
    return 1;
}

static int check_group_coordinator_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int        str_len;

    DEBUG_LOG(DBG_PARSER, p, "Kafka group coordinator\n");

    str_len = get_short_string_len(ptr, pleft);
    ptr += str_len; size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka group coordinator client id\n");
        return size_left < 0 ? -1 : str_len;
    } 
    str_len = get_short_string_len(ptr, pleft);
    size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka group coordinator group id\n");
        return size_left < 0 ? -1 : str_len;
    } 

    data->checked_request = true;
    return 1;
}

static int check_controlled_shutdown_request(dpi_packet_t *p, kafka_data_t * data, uint8_t *ptr, int *pleft, int size_left)
{
    int        str_len;

    DEBUG_LOG(DBG_PARSER, p, "Kafka Controlled shutdown request\n");

    str_len = get_short_string_len(ptr, pleft);
    size_left -= str_len;
    if (str_len <= 0 || size_left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "Not Kafka client id\n");
        return size_left < 0 ? -1 : str_len;
    }

    data->checked_request = true;
    return 1;
}

static int check_api_key(dpi_packet_t *p, kafka_data_t * data, uint16_t api_key, uint16_t version_id, uint8_t *ptr, int * pleft, int size_left)
{
    switch (api_key) {
    case PRODUCE                  :
        return check_produce_request(p, data, ptr, pleft, size_left);
    case FETCH                    :
        return check_fetch_request(p, data, ptr, pleft, version_id, size_left);
    case LIST_OFFSETS             :
        return check_list_offsets_request(p, data, ptr, pleft, size_left);
    case METADATA                 :
        return check_metadata_request(p, data, ptr, pleft, size_left);
    case LEADER_AND_ISR           :
        return check_leader_and_isr_request(p, data, ptr, pleft, size_left);
    case STOP_REPLICA             :
        return check_replica_request(p, data, ptr, pleft, size_left);
    case UPDATE_METADATA_KEY      :
        return check_update_metadata_key_request(p, data, ptr, pleft, size_left);
    case CONTROLLED_SHUTDOWN_KEY  :
        return check_controlled_shutdown_request(p, data, ptr, pleft, size_left);
    case OFFSET_COMMIT            :
        return check_offset_commit_request(p, data, ptr, version_id, pleft, size_left);
    case OFFSET_FETCH             :
        return check_offset_fetch_request(p, data, ptr, pleft, size_left);
    case GROUP_COORDINATOR        :
        return check_group_coordinator_request(p, data, ptr, pleft, size_left);
    case JOIN_GROUP               :
    case HEARTBEAT                :
    case LEAVE_GROUP              :
    case SYNC_GROUP               :
    case DESCRIBE_GROUPS          :
    case LIST_GROUPS              :
    default:
        DEBUG_LOG(DBG_PARSER, p, "Kafka unchecked api key: %d\n",api_key);
        data->checked_request = false;
        return 1;
    }
}

static int check_corr_id_valid(dpi_packet_t *p,  kafka_data_t *data)
{
    int matched=0;
    int round= data->checked_request ? 1: 2;
    int i,j;

    for (i=0; i < data->client.corr_id_cnt; i++) {
        for (j=0; j<data->client.corr_id_cnt; j++) {
            if ((i != j) && (data->client.corr_id[i] == data->client.corr_id[j])) {
                DEBUG_LOG(DBG_PARSER, p, "Kafka client correlation id not match\n");
                return -1;
            }
        }
    }
    for (i=0; i < data->server.corr_id_cnt; i++) {
        for (j=0; j<data->server.corr_id_cnt; j++) {
            if ((i != j) && (data->server.corr_id[i] == data->server.corr_id[j])) {
                DEBUG_LOG(DBG_PARSER, p, "Kafka server correlation id not match\n");
                return -1;
            }
        }
    }
    for (i=0; i < data->server.corr_id_cnt; i++) {
        for (j=0; j<data->client.corr_id_cnt; j++) {
            if (data->server.corr_id[i] == data->client.corr_id[j]) {
                matched ++;
                DEBUG_LOG(DBG_PARSER, p, "Kafka match correlation id\n");
                if (matched >= round) {
                    return 1;
                }
                break;
            }
        }
    }
    if (data->server.corr_id_cnt >= 2) {
        return -1;
    } else {
        return 0;
    }
}

static void kafka_parser(dpi_packet_t *p)
{
    kafka_data_t *data;
    uint8_t *ptr;
    uint32_t len;

    DEBUG_LOG(DBG_PARSER, p, "session_id=%u\n", p->session->id);

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not kafka: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }
        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }
        dpi_session_t *s = p->session;
        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;
        dpi_put_parser_data(p, data);
    }

    kafka_wing_t *w;
    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + shift;
        len = dpi_pkt_len(p) - shift;
    } else {
        DEBUG_LOG(DBG_PARSER, p, "packet assemble error\n");
        dpi_fire_parser(p);
        return;
    }
    int left = len;

    if (w->left > 0) {
        if (w->left < len) {
            ptr  += w->left;
            left -= w->left;
            w->seq += w->left;
            w->left = 0;
            dpi_set_asm_seq(p, w->seq);
        } else {
            w->left -= len;
            w->seq += len;
            dpi_set_asm_seq(p, w->seq);
            return;
        }
    } else if(w->left < 0) {
        DEBUG_LOG(DBG_PARSER, p, "w->left < 0\n");
        dpi_fire_parser(p);
        return;
    }
    if (left < 4) return;
    int32_t size  = GET_BIG_INT32(ptr);
    int16_t api_key = 0;
    int16_t api_version = 0;
    int32_t corr_id = 0;

    ptr += 4;
    left -= 4;
    w->left = size;
    //request
    if (dpi_is_client_pkt(p)) {
        if (size > MAX_KAFKA_PACKET) {
            DEBUG_LOG(DBG_PARSER, p, "Kafka request size too large or small:%d,left: %d\n",size,left);
            dpi_fire_parser(p);
            return;
        }
        if (size != left) {
            DEBUG_LOG(DBG_PARSER, p, "Warning, Kafka size not match, truck packet. size:%d,left: %d\n",size,left);
        }
        if (left < 12) {
            w->left = 0;
            return;
        }

        api_key  = GET_BIG_INT16(ptr);
        if (api_key > 16) {
            DEBUG_LOG(DBG_PARSER, p, "Wrong Kafka api key\n");
            dpi_fire_parser(p);
            return;
        }
        ptr += 2;left -= 2;
        api_version     = GET_BIG_INT16(ptr);
        if (api_version > 4) {
            DEBUG_LOG(DBG_PARSER, p, "Wrong Kafka api version\n");
            dpi_fire_parser(p);
            return;
        }
        ptr += 2;left -= 2;
        corr_id     = GET_BIG_INT32(ptr);
        ptr += 4;left -= 4;
        int res = check_api_key(p, data, api_key, api_version, ptr, &left, size-8);
        int parsed = len - left;
        if (res < 0) {
            DEBUG_LOG(DBG_PARSER, p, "Invalid Kafka request:%d\n",api_key);
            dpi_fire_parser(p);
            return;
        } else if (res == 0) {
            if (parsed > 1024) {
                //if it already parse enough data and no error found, it should be a valid request
                data->checked_request = true;
            } else {
                DEBUG_LOG(DBG_PARSER, p, "Kafka not enough packet data\n");
                w->left = 0;
                return;
            }
        }

        DEBUG_LOG(DBG_PARSER, p, "Valid Kafka request:%d\n",api_key);
        if (p->ep->kafka_svr || data->valid_request) {
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            return;
        }
        if (data->client.corr_id_cnt < 2) {
            data->client.corr_id[data->client.corr_id_cnt++] = corr_id;
        }

        //if get two valid client request, finalize it
        if (data->client.corr_id_cnt >= 2 && data->checked_request) {
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            return;
        }
    } else { //response
        if (size > MAX_KAFKA_PACKET) {
            DEBUG_LOG(DBG_PARSER, p, "Kafka response size to large:%d\n",size);
            dpi_fire_parser(p);
            return;
        }
        if (left < 4) {
            w->left = 0;
            return;
        }
        corr_id     = GET_BIG_INT32(ptr);
        if (data->server.corr_id_cnt < 4) {
            data->server.corr_id[data->server.corr_id_cnt++] = corr_id;
        }
    }

    if (left < 0) {
        left = 0;
    }
    int  parsed = size > (len - left) ? (len - left) : size;
    w->left -= parsed;
    w->seq += parsed+4;
    dpi_set_asm_seq(p, w->seq);
    int res = check_corr_id_valid(p,  data);

    if (res == 1) {
        if (p->session->flags & DPI_SESS_FLAG_INGRESS) {
            p->ep->kafka_svr = true;
        }
        dpi_finalize_parser(p);
        dpi_ignore_parser(p);
    } else if (res == -1) {
        dpi_fire_parser(p);
    }
}

static void kafka_midstream(dpi_packet_t *p)
{
    uint8_t *ptr;
    int len;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER,NULL);

    ptr = dpi_pkt_ptr(p);
    len = dpi_pkt_len(p);

    int32_t size;
    int16_t api_key = 0;
    int16_t api_version = 0;
    kafka_data_t data;

    if (len >= 12) {
        size  = GET_BIG_INT32(ptr);
        if (size > MAX_KAFKA_PACKET) {
            goto Exit;
        }
        ptr += 4;len -= 4;
        api_key  = GET_BIG_INT16(ptr);
        if (api_key > 16) {
            goto Exit;
        }
        ptr += 2;len -= 2;
        api_version     = GET_BIG_INT16(ptr);
        if (api_version > 4) {
            goto Exit;
        }
        ptr += 2;len -= 2;
        ptr += 4;len -= 4;
        int res = check_api_key(p, &data, api_key, api_version, ptr, &len, size-8);
        if (res > 0 && data.checked_request) {
            DEBUG_LOG(DBG_PARSER, p, "Kafka midstream\n");
            dpi_finalize_parser(p);
            dpi_ignore_parser(p);
            return;
        }
    }

Exit:
    dpi_fire_parser(p);
}

static void kafka_new_session(dpi_packet_t *p)
{
    if (p->session->server.port >= 1024) {
        dpi_hire_parser(p);
    }
}

static void kafka_new_mid_sess(dpi_packet_t *p)
{
    if (p->session->server.port >= 1024) {
        dpi_hire_parser(p);
    }
}

static void kafka_delete_data(void *data)
{
    free(data);
}

static dpi_parser_t dpi_parser_kafka = {
    .new_session = kafka_new_session,
    .delete_data = kafka_delete_data,
    .parser = kafka_parser,
    .new_mid_sess = kafka_new_mid_sess,
    .midstream = kafka_midstream,
    .name = "kafka",
    .ip_proto = IPPROTO_TCP,
    .type = DPI_PARSER_KAFKA,
};

dpi_parser_t *dpi_kafka_parser(void)
{
    return &dpi_parser_kafka;
}


