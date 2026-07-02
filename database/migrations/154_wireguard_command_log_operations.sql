ALTER TABLE mikrotik_station_command_logs
    DROP CONSTRAINT IF EXISTS mikrotik_station_command_logs_operation_check;

ALTER TABLE mikrotik_station_command_logs
    ADD CONSTRAINT mikrotik_station_command_logs_operation_check
    CHECK (
        operation IN (
            'CHECK',
            'APPLY',
            'REMOVE',
            'WIREGUARD_STATION_INTERFACE',
            'WIREGUARD_STATION_CLIENT',
            'WIREGUARD_STATION_REMOVE',
            'WIREGUARD_HUB_CLIENT',
            'WIREGUARD_HUB_REMOVE',
            'WIREGUARD_STATION_SIDE',
            'WIREGUARD_HUB_INTERFACE',
            'WIREGUARD_HUB_PEER',
            'WIREGUARD_APPLY',
            'WIREGUARD_REMOVE'
        )
    );
