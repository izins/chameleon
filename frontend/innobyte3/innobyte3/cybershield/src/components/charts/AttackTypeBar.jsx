import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export const AttackTypeBar = ({ data }) => {
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 20, right: 30, left: 0, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" vertical={false} />
          <XAxis dataKey="name" stroke="#a0aec0" tick={{ fill: '#a0aec0', fontSize: 12 }} />
          <YAxis stroke="#a0aec0" tick={{ fill: '#a0aec0', fontSize: 12 }} />
          <Tooltip 
            cursor={{ fill: 'rgba(0, 255, 136, 0.05)' }}
            contentStyle={{ backgroundColor: '#1a2230', borderColor: 'rgba(0, 255, 136, 0.15)', color: '#fff' }}
          />
          <Bar dataKey="count" fill="#00ff88" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
