import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { MeasurementChartData } from '../types/dashboard';

interface MeasurementChartProps {
  data: MeasurementChartData[];
}

export function MeasurementChart({ data }: MeasurementChartProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Clients by Measurement</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis type="number" />
          <YAxis dataKey="measurement" type="category" width={120} />
          <Tooltip
            content={({ active, payload }) => {
              if (active && payload && payload.length) {
                return (
                  <div className="bg-white p-3 border rounded shadow-lg">
                    <p className="text-sm font-mono text-gray-600 mb-1">{payload[0].payload.fullMeasurement}</p>
                    <p className="text-sm font-bold">Count: {payload[0].value}</p>
                  </div>
                );
              }
              return null;
            }}
          />
          <Bar dataKey="count" fill="#3498db" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
