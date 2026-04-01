"use client";

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Search, AlertCircle, CheckCircle, ShieldAlert, Loader2 } from 'lucide-react';

export const ThreatSandbox = () => {
  const [input, setInput] = useState("");
  const [status, setStatus] = useState<'idle' | 'scanning' | 'complete'>('idle');
  const [score, setScore] = useState(0);

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input) return;
    
    setStatus('scanning');
    setScore(0);
    
    // Simulate complex scanning
    setTimeout(() => {
      setStatus('complete');
      // Generate a "realistic" threat score based on common phish patterns
      const isSus = input.includes('login') || input.includes('verify') || input.includes('.xyz') || input.includes('bit.ly');
      setScore(isSus ? Math.floor(Math.random() * 40) + 60 : Math.floor(Math.random() * 10) + 1);
    }, 2500);
  };

  return (
    <section className="py-24 px-6 bg-surface-container-lowest">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-primary font-headline font-bold uppercase tracking-[0.3em] text-sm">Interactive Demo</h2>
          <h3 className="text-4xl md:text-5xl font-headline font-bold text-white tracking-tight">
            Challenge the <span className="text-primary italic">Sovereign</span>.
          </h3>
          <p className="text-on-surface-variant font-light text-lg">Input any URL or communication snippet to witness the "One Threat Score" detonation protocol.</p>
        </div>

        <div className="glass-panel p-8 md:p-12 rounded-[2.5rem] border border-primary/20 shadow-[0_0_80px_rgba(49,227,104,0.05)] relative overflow-hidden bg-black/40">
          <form onSubmit={handleScan} className="relative z-10 flex flex-col md:flex-row gap-4 mb-12">
            <div className="relative flex-1 group">
              <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                <Search className="w-5 h-5 text-on-surface-variant/40 group-focus-within:text-primary transition-colors" />
              </div>
              <input 
                type="text" 
                placeholder="Paste URL, email header, or text snippet here..."
                className="w-full bg-background/50 border border-outline/20 rounded-2xl py-5 pl-12 pr-6 text-white focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/20 transition-all font-light"
                value={input}
                onChange={(e) => setInput(e.target.value)}
              />
            </div>
            <motion.button 
              disabled={status === 'scanning'}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              className="bg-primary text-black font-headline font-bold px-10 py-5 rounded-2xl shadow-lg shadow-primary/20 hover:bg-primary-dark transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3"
            >
              {status === 'scanning' ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  ANALYZING
                </>
              ) : (
                <>
                  INITIATE SCAN
                  <Shield className="w-5 h-5" />
                </>
              )}
            </motion.button>
          </form>

          <AnimatePresence mode="wait">
            {status === 'scanning' && (
              <motion.div 
                key="scanning"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="flex flex-col items-center py-12 space-y-6"
              >
                <div className="relative h-32 w-32">
                  <motion.div 
                    animate={{ rotate: 360 }}
                    transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    className="absolute inset-0 border-4 border-primary/20 border-t-primary rounded-full shadow-[0_0_20px_rgba(49,227,104,0.3)]"
                  />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Shield className="w-12 h-12 text-primary animate-pulse" />
                  </div>
                </div>
                <div className="text-center space-y-2">
                  <p className="text-primary font-headline font-bold tracking-widest text-xs">NEURAL ANALYSIS IN PROGRESS</p>
                  <div className="flex gap-1 justify-center">
                    {["Deepfake Check", "URL Detonation", "Metadata Forensic", "Pattern Match"].map((step, i) => (
                      <motion.div 
                        key={i}
                        animate={{ opacity: [0.3, 1, 0.3] }}
                        transition={{ duration: 1.5, repeat: Infinity, delay: i * 0.2 }}
                        className="text-[10px] text-on-surface-variant bg-surface px-2 py-1 rounded border border-outline/10 uppercase"
                      >
                        {step}
                      </motion.div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {status === 'complete' && (
              <motion.div 
                key="complete"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="grid md:grid-cols-2 gap-12 items-center py-4"
              >
                <div className="flex justify-center">
                  <div className="relative h-64 w-64 flex items-center justify-center">
                    <svg className="w-full h-full -rotate-90">
                      <circle cx="128" cy="128" r="110" className="stroke-surface-high fill-none border-outline border" strokeWidth="12" />
                      <motion.circle 
                        initial={{ strokeDasharray: "0, 1000" }}
                        animate={{ strokeDasharray: `${(score / 100) * 690}, 1000` }}
                        transition={{ duration: 1.5, ease: "easeOut" }}
                        cx="128" cy="128" r="110" 
                        className={`fill-none ${score > 50 ? 'stroke-error' : 'stroke-primary'}`} 
                        strokeWidth="12" 
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center space-y-1">
                      <span className={`text-6xl font-headline font-bold ${score > 50 ? 'text-error' : 'text-primary'} glow-text`}>{score}</span>
                      <span className="text-[10px] font-headline text-on-surface-variant font-bold tracking-widest uppercase">THREAT SCORE</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className={`p-6 rounded-2xl border-l-[6px] ${score > 50 ? 'bg-error/5 border-error' : 'bg-primary/5 border-primary'} shadow-xl`}>
                    <div className="flex items-center gap-3 mb-3">
                      {score > 50 ? (
                        <ShieldAlert className="w-6 h-6 text-error" />
                      ) : (
                        <ShieldCheck className="w-6 h-6 text-primary" />
                      )}
                      <h4 className="text-2xl font-headline font-bold text-white tracking-tight">
                        {score > 50 ? 'Attack Neutralized' : 'Minimal Risk Detected'}
                      </h4>
                    </div>
                    <p className="text-on-surface-variant text-sm font-light leading-relaxed">
                      {score > 50 
                        ? 'System detected high-frequency synthetic artifacts and adversarial prompt injection consistent with state-sponsored scam infrastructure.' 
                        : 'No known malicious patterns identified. Semantic integrity and origin metadata appear within normal sovereign boundaries.'}
                    </p>
                  </div>

                  <div className="flex gap-4">
                    <button className="flex-1 border border-outline/20 bg-surface/50 text-white font-headline text-xs font-bold py-4 rounded-xl hover:bg-surface transition-colors" onClick={() => setStatus('idle')}>
                      RESET SCANNER
                    </button>
                    <button className={`flex-1 ${score > 50 ? 'bg-error text-black' : 'bg-primary text-black'} font-headline text-xs font-bold py-4 rounded-xl shadow-lg transition-all`}>
                      {score > 50 ? 'BLOCK SOURCE' : 'VERIFY IDENTITY'}
                    </button>
                  </div>
                </div>
              </motion.div>
            )}

            {status === 'idle' && (
              <motion.div 
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-20 border-2 border-dashed border-outline/10 rounded-3xl"
              >
                <AlertCircle className="w-12 h-12 text-on-surface-variant/20 mb-4" />
                <p className="text-on-surface-variant/40 font-light text-sm">Waiting for input to secure your perimeter.</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
};

const ShieldCheck = ({ className }: { className: string }) => (
  <CheckCircle className={className} />
);
