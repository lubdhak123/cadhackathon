"use client";

import React, { useState, useEffect } from 'react';
import { Shield, Menu, X } from 'lucide-react';
import { motion } from 'framer-motion';

export const Navbar = () => {
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${isScrolled ? 'bg-background/80 backdrop-blur-xl py-4 shadow-2xl shadow-black/50' : 'bg-transparent py-6'}`}>
      <div className="max-w-7xl mx-auto px-6 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Shield className="text-primary w-8 h-8 drop-shadow-[0_0_8px_rgba(49,227,104,0.4)]" />
          <span className="text-xl font-bold tracking-tighter text-on-background font-headline">
            FRAUD SHIELD <span className="text-primary">AI</span>
          </span>
        </div>

        <div className="hidden md:flex items-center gap-10">
          {['Product', 'Tech Stack', 'Impact'].map((item) => (
            <a
              key={item}
              href={`#${item.toLowerCase().replace(' ', '-')}`}
              className="text-sm font-medium text-on-surface-variant hover:text-primary transition-colors font-headline tracking-tight"
            >
              {item}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <button className="bg-primary text-black font-bold px-6 py-2 rounded-lg hover:bg-primary-dark transition-all active:scale-95 duration-150 ease-in-out font-headline text-sm">
            Analyze Threat
          </button>
          <button className="md:hidden text-on-background">
            <Menu className="w-6 h-6" />
          </button>
        </div>
      </div>
      <div className={`bg-gradient-to-r from-transparent via-primary/20 to-transparent h-[1px] w-full absolute bottom-0 transition-opacity duration-500 ${isScrolled ? 'opacity-100' : 'opacity-0'}`}></div>
    </nav>
  );
};
