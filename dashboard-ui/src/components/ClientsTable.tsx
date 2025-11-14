import { useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { ClientAttestationWithProxy } from '../types/dashboard';

interface ClientsTableProps {
  clients: ClientAttestationWithProxy[];
}

const ITEMS_PER_PAGE = 5;

export function ClientsTable({ clients }: ClientsTableProps) {
  const [currentPage, setCurrentPage] = useState(1);

  const totalPages = Math.ceil(clients.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const endIndex = startIndex + ITEMS_PER_PAGE;
  const currentClients = clients.slice(startIndex, endIndex);

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const formatMeasurement = (measurement: string) => {
    // Find the first non-zero character
    const firstNonZero = measurement.search(/[^0]/);
    if (firstNonZero === -1) {
      return '0x0000...';
    }
    // Extract non-zero portion and show first 12 chars
    const nonZeroPart = measurement.substring(firstNonZero);
    return '0x...' + nonZeroPart.substring(0, 12);
  };

  const formatID = (id: string | undefined) => {
    if (!id || id === '' || /^0+$/.test(id)) {
      return 'N/A';
    }
    // Show first 8 chars and last 8 chars
    if (id.length > 16) {
      return `${id.substring(0, 8)}...${id.substring(id.length - 8)}`;
    }
    return id;
  };

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <div className="px-6 py-4 border-b">
        <h3 className="text-lg font-semibold text-gray-900">Attestation Records</h3>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attestation ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Measurement</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Family ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Image ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Chip ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">TCB</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Debug</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">SMT</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Connected</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Proxy</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {currentClients.map((client) => (
              <tr key={client.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                  {client.id.substring(0, 24)}...
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600">
                  {formatMeasurement(client.measurement)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600" title={client.family_id || 'N/A'}>
                  {formatID(client.family_id)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600" title={client.image_id || 'N/A'}>
                  {formatID(client.image_id)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600" title={client.chip_id || 'N/A'}>
                  {formatID(client.chip_id)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {client.tcb_version}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    client.debug_enabled ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                  }`}>
                    {client.debug_enabled ? 'Yes' : 'No'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    client.smt_enabled ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                  }`}>
                    {client.smt_enabled ? 'Yes' : 'No'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {formatDate(client.connected_at)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  {client.proxy_address}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="relative group inline-block">
                    <span
                      className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full cursor-help ${
                        client.verify_result === 'allowed' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                      }`}
                    >
                      {client.verify_result.toUpperCase()}
                    </span>
                    {client.verify_result === 'denied' && client.verify_reason && (
                      <div className="absolute z-10 invisible group-hover:visible bg-gray-900 text-white text-xs rounded py-2 px-3 bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-64 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                        {client.verify_reason}
                        <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                          <div className="border-4 border-transparent border-t-gray-900"></div>
                        </div>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="px-6 py-4 flex items-center justify-between border-t bg-gray-50">
        <div className="text-sm text-gray-700">
          Page {currentPage} of {totalPages} ({clients.length} total)
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="px-3 py-1 bg-white border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>
          <button
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
            className="px-3 py-1 bg-white border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
          >
            Next
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
