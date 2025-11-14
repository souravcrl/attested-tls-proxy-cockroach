import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  color?: string;
}

export function MetricCard({ title, value, icon: Icon, color = 'text-blue-600' }: MetricCardProps) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
        </div>
        <div className={`p-3 rounded-full bg-gray-100 ${color}`}>
          <Icon className="w-8 h-8" />
        </div>
      </div>
    </div>
  );
}
