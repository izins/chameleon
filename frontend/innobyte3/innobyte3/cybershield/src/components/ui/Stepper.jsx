import React from 'react';
import { Check, Clock, Circle } from 'lucide-react';

export const Stepper = ({ steps }) => {
  return (
    <div className="space-y-6">
      {steps.map((step, index) => {
        const isDone = step.status === 'Done';
        const isInProgress = step.status === 'In Progress';
        
        return (
          <div key={step.id || index} className="relative flex gap-4 animate-fade-up" style={{ animationDelay: `${index * 0.1}s` }}>
            {/* Connecting Line */}
            {index !== steps.length - 1 && (
              <div className={`absolute top-8 left-[19px] w-[2px] h-full -ml-px ${isDone ? 'bg-brand-secondary' : 'bg-gray-700'}`}></div>
            )}
            
            {/* Step Icon */}
            <div className="relative z-10 flex-shrink-0">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center border-2 
                ${isDone ? 'bg-[rgba(0,196,106,0.1)] border-brand-secondary text-brand-secondary shadow-[0_0_15px_rgba(0,196,106,0.4)]' : 
                  isInProgress ? 'bg-[rgba(245,158,11,0.1)] border-brand-warning text-brand-warning animate-pulse-amber' : 
                  'bg-brand-bg-surface border-gray-600 text-gray-500'}`}
              >
                {isDone ? <Check size={20} /> : isInProgress ? <Clock size={20} /> : <Circle size={16} />}
              </div>
            </div>
            
            {/* Step Content */}
            <div className={`flex-1 pb-2 ${isDone ? 'opacity-80' : isInProgress ? 'opacity-100' : 'opacity-50'}`}>
              <h4 className={`text-lg font-medium ${isDone ? 'text-white' : isInProgress ? 'text-brand-warning' : 'text-gray-400'}`}>
                {index + 1}. {step.title}
              </h4>
              <p className="text-gray-400 text-sm mt-1">{step.description}</p>
              
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="text-xs bg-brand-bg-surface px-2 py-1 rounded border border-gray-700 text-gray-300">
                  Role: <span className="font-mono text-brand-primary">{step.role}</span>
                </span>
                <span className="text-xs bg-brand-bg-surface px-2 py-1 rounded border border-gray-700 text-gray-300">
                  SLA: <span className="text-brand-info">{step.sla}</span>
                </span>
                {step.legalRef && (
                  <span className="text-xs bg-[rgba(255,255,255,0.05)] px-2 py-1 rounded border border-gray-600 text-gray-200">
                    ⚖️ {step.legalRef}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
