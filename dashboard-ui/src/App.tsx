import { useState, useEffect } from 'react';
import { Users, Activity, Server, AlertTriangle } from 'lucide-react';
import { MetricCard } from './components/MetricCard';
import { FailureTypeChart } from './components/FailureTypeChart';
import { ProxyChart } from './components/ProxyChart';
import { ClientsTable } from './components/ClientsTable';
import { AggregatedData, FailureTypeChartData, ProxyChartData } from './types/dashboard';

function App() {
  const [data, setData] = useState<AggregatedData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string>('');

  const fetchData = async () => {
    try {
      const response = await fetch('/api/aggregated');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const jsonData: AggregatedData = await response.json();
      setData(jsonData);
      setLastUpdated(new Date().toLocaleTimeString());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md">
          <h2 className="text-xl font-bold text-red-600 mb-2">Error Loading Dashboard</h2>
          <p className="text-gray-600">{error || 'No data available'}</p>
          <button
            onClick={() => {
              setLoading(true);
              fetchData();
            }}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Prepare chart data
  const failureTypeData: FailureTypeChartData[] = Object.entries(data.failure_type_stats || {}).map(([type, count]) => ({
    type: type.length > 20 ? type.substring(0, 20) + '...' : type,
    count,
    fullType: type,
  }));

  const proxyData: ProxyChartData[] = Object.entries(data.attestations_by_proxy).map(([name, value]) => ({
    name,
    value,
  }));

  // Calculate total denied clients
  const totalDenied = Object.values(data.failure_type_stats || {}).reduce((sum, count) => sum + count, 0);

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-2xl">🔒</span>
              <h1 className="text-3xl font-bold text-gray-900">Cluster Attestation Dashboard</h1>
            </div>
            <div className="text-sm text-gray-500">
              Last updated: {lastUpdated}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <MetricCard
            title="Total Clients"
            value={data.total_clients}
            icon={Users}
            color="text-blue-600"
          />
          <MetricCard
            title="Active Connections"
            value={data.active_clients}
            icon={Activity}
            color="text-green-600"
          />
          <MetricCard
            title="Proxy Nodes"
            value={data.proxy_nodes.length}
            icon={Server}
            color="text-purple-600"
          />
          <MetricCard
            title="Denied Clients"
            value={totalDenied}
            icon={AlertTriangle}
            color="text-red-600"
          />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <FailureTypeChart data={failureTypeData} />
          <ProxyChart data={proxyData} />
        </div>

        {/* Table */}
        <ClientsTable clients={data.clients} />
      </main>
    </div>
  );
}

export default App;
