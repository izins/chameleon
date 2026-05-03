import React, { useEffect } from 'react';
import { X, CheckCircle, AlertTriangle, Info } from 'lucide-react';

export const Toast = ({ message, type = 'info', onClose, duration = 5000 }) => {
  useEffect(() => {
    if (duration) {
      const timer = setTimeout(() => {
        onClose();
      }, duration);
      return () => clearTimeout(timer);
    }
  }, [duration, onClose]);

  const icons = {
    success: <CheckCircle className="text-brand-secondary" size={20} />,
    error: <AlertTriangle className="text-brand-danger" size={20} />,
    info: <Info className="text-brand-info" size={20} />
  };

  const borders = {
    success: 'border-brand-secondary',
    error: 'border-brand-danger',
    info: 'border-brand-info'
  };

  return (
    <div className={`fixed bottom-4 right-4 z-50 flex items-center gap-3 bg-brand-bg-card border ${borders[type]} p-4 rounded-lg shadow-lg animate-fade-up`}>
      {icons[type]}
      <p className="text-white text-sm font-medium">{message}</p>
      <button onClick={onClose} className="ml-4 text-gray-400 hover:text-white">
        <X size={16} />
      </button>
    </div>
  );
};
