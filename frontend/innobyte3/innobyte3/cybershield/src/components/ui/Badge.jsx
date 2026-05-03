import React from 'react';

export const Badge = ({ children, variant = 'default', className = '' }) => {
  const baseStyles = "px-2.5 py-0.5 rounded-full text-xs font-medium border";
  const variants = {
    default: "bg-brand-bg-surface text-gray-300 border-gray-700",
    success: "bg-[rgba(0,196,106,0.1)] text-brand-secondary border-brand-secondary/30",
    danger: "bg-[rgba(255,59,92,0.1)] text-brand-danger border-brand-danger/30",
    warning: "bg-[rgba(245,158,11,0.1)] text-brand-warning border-brand-warning/30",
    info: "bg-[rgba(56,189,248,0.1)] text-brand-info border-brand-info/30",
  };

  return (
    <span className={`${baseStyles} ${variants[variant] || variants.default} ${className}`}>
      {children}
    </span>
  );
};
