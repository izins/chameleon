import React from 'react';

export const Card = ({ children, className = '', glow = false }) => {
  return (
    <div className={`bg-brand-bg-card border border-brand-border rounded-xl p-5 ${glow ? 'shadow-brand-glow hover:glow-active transition-shadow duration-300' : ''} ${className}`}>
      {children}
    </div>
  );
};

export const CardHeader = ({ children, className = '' }) => (
  <div className={`mb-4 flex justify-between items-center ${className}`}>
    {children}
  </div>
);

export const CardTitle = ({ children, className = '' }) => (
  <h3 className={`text-lg font-semibold text-white ${className}`}>
    {children}
  </h3>
);

export const CardContent = ({ children, className = '' }) => (
  <div className={className}>
    {children}
  </div>
);
