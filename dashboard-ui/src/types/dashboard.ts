// TypeScript types matching the Go backend API responses

export interface ProxyNode {
  id: string;
  address: string;
  healthy: boolean;
}

export interface ClientAttestationWithProxy {
  id: string;
  client_id: string;
  measurement: string;
  tcb_version: string;
  debug_enabled: boolean;
  smt_enabled: boolean;
  connected_at: string;
  disconnected_at?: string | null;
  proxy_address: string;
  verify_result: 'allowed' | 'denied';
  verify_reason?: string;
  bytes_in?: number;
  bytes_out?: number;
  family_id?: string;
  image_id?: string;
  chip_id?: string;
}

export interface AggregatedData {
  total_clients: number;
  active_clients: number;
  attestations_by_proxy: Record<string, number>;
  measurement_stats: Record<string, number>;
  failure_type_stats: Record<string, number>;
  clients: ClientAttestationWithProxy[];
  proxy_nodes: ProxyNode[];
  last_updated: string;
}

export interface MeasurementChartData {
  measurement: string;
  count: number;
  fullMeasurement: string;
}

export interface ProxyChartData {
  name: string;
  value: number;
  [key: string]: string | number; // Allow additional properties for Recharts compatibility
}

export interface FailureTypeChartData {
  type: string;
  count: number;
  fullType: string;
}
