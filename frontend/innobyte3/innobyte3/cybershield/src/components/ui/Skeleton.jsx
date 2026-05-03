import React from 'react';

export const Skeleton = ({ className = '', variant = 'rectangular' }) => {
  const baseClass = "animate-pulse bg-brand-bg-surface/50 border border-brand-border/30";
  const variants = {
    rectangular: "rounded-md",
    circular: "rounded-full",
    text: "rounded-sm h-4",
  };
  
  return (
    <div className={`${baseClass} ${variants[variant]} ${className}`}></div>
  );
};
