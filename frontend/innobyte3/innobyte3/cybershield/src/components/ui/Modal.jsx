import React from 'react';
import { X } from 'lucide-react';

export const Modal = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-up">
      <div className="bg-brand-bg-card border border-brand-border rounded-xl w-full max-w-lg mx-4 shadow-2xl shadow-brand-primary/10 overflow-hidden">
        <div className="flex justify-between items-center p-4 border-b border-brand-border/50 bg-brand-bg-surface">
          <h2 className="text-xl font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
            <X size={20} />
          </button>
        </div>
        <div className="p-6">
          {children}
        </div>
      </div>
    </div>
  );
};
