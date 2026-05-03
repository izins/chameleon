import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Zap, BarChart3, Lock, ChevronDown, CheckCircle, ArrowRight, Globe, Cpu, Eye, FileText, Users, Star, Menu, X } from 'lucide-react';

const fadeUp = { hidden: { opacity: 0, y: 30 }, show: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.25, 0.4, 0.25, 1] } } };
const stagger = { show: { transition: { staggerChildren: 0.1 } } };

/* ─── Navbar ─── */
const Navbar = () => {
  const [open, setOpen] = useState(false);
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-strong">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <a href="/" className="flex items-center gap-2.5">
          <img src="/image/logo.png" alt="Cameleon Logo" className="w-40 h-40 object-contain" />

        </a>
        <div className="hidden md:flex items-center gap-8">
          {['Features', 'Pricing', 'FAQ'].map(l => (
            <a key={l} href={`#${l.toLowerCase()}`} className="text-sm text-neutral-400 hover:text-white transition-colors">{l}</a>
          ))}
        </div>
        <div className="hidden md:flex items-center gap-3">
          <a href="#roles" className="text-sm text-neutral-300 hover:text-white transition-colors px-4 py-2">Log in</a>
          <a href="#roles" className="text-sm font-medium bg-brand-primary text-black px-5 py-2 rounded-lg hover:bg-brand-secondary transition-colors">Get Started</a>
        </div>
        <button className="md:hidden text-white" onClick={() => setOpen(!open)}>{open ? <X size={22} /> : <Menu size={22} />}</button>
      </div>
      <AnimatePresence>{open && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="md:hidden bg-brand-bg-surface border-t border-brand-border overflow-hidden">
          <div className="p-4 space-y-3">
            {['Features', 'Pricing', 'FAQ'].map(l => <a key={l} href={`#${l.toLowerCase()}`} className="block text-neutral-300 py-2" onClick={() => setOpen(false)}>{l}</a>)}
            <a href="#roles" className="block text-center bg-brand-primary text-black py-2.5 rounded-lg font-medium">Get Started</a>
          </div>
        </motion.div>
      )}</AnimatePresence>
    </nav>
  );
};

/* ─── Hero ─── */
const Hero = () => (
  <section className="relative pt-32 pb-24 overflow-hidden">
    {/* Base ambient glow */}
    <div className="absolute inset-0 bg-radial-glow" />
    <div className="absolute inset-0 bg-grid opacity-40" />

    {/* ✦ Neon green orb — large, top center */}
    <div className="absolute top-[-120px] left-1/2 -translate-x-1/2 w-[700px] h-[400px] rounded-full opacity-30 blur-[120px] pointer-events-none"
      style={{ background: 'radial-gradient(circle, rgba(0,232,123,0.45) 0%, rgba(0,232,123,0.08) 50%, transparent 80%)' }} />

    {/* ✦ Neon orb — small left */}
    <motion.div
      animate={{ opacity: [0.2, 0.5, 0.2], scale: [1, 1.15, 1] }}
      transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
      className="absolute top-40 left-[8%] w-48 h-48 rounded-full blur-[80px] pointer-events-none"
      style={{ background: 'radial-gradient(circle, rgba(0,232,123,0.5) 0%, transparent 70%)' }}
    />

    {/* ✦ Neon orb — small right */}
    <motion.div
      animate={{ opacity: [0.15, 0.4, 0.15], scale: [1, 1.2, 1] }}
      transition={{ duration: 5, repeat: Infinity, ease: 'easeInOut', delay: 1.5 }}
      className="absolute top-28 right-[10%] w-56 h-56 rounded-full blur-[90px] pointer-events-none"
      style={{ background: 'radial-gradient(circle, rgba(0,232,123,0.4) 0%, transparent 70%)' }}
    />



    {/* ✦ Floating neon particles */}
    {[
      { top: '20%', left: '15%', size: 3, dur: 3, delay: 0 },
      { top: '35%', left: '80%', size: 2, dur: 4, delay: 1 },
      { top: '60%', left: '25%', size: 2.5, dur: 3.5, delay: 0.5 },
      { top: '45%', left: '70%', size: 2, dur: 5, delay: 2 },
      { top: '25%', left: '55%', size: 1.5, dur: 4.5, delay: 1.2 },
      { top: '55%', left: '40%', size: 2, dur: 3.8, delay: 0.8 },
      { top: '15%', left: '5%', size: 2, dur: 4.2, delay: 0.3 },
      { top: '70%', left: '12%', size: 1.5, dur: 3.2, delay: 1.8 },
      { top: '10%', left: '45%', size: 2.5, dur: 5.5, delay: 0.7 },
      { top: '50%', left: '90%', size: 2, dur: 3.6, delay: 1.5 },
      { top: '30%', left: '35%', size: 1.5, dur: 4.8, delay: 2.2 },
      { top: '65%', left: '65%', size: 3, dur: 3.4, delay: 0.4 },
      { top: '40%', left: '5%', size: 2, dur: 4.4, delay: 1.1 },
      { top: '75%', left: '50%', size: 1.5, dur: 5.2, delay: 0.9 },
      { top: '18%', left: '92%', size: 2.5, dur: 3.9, delay: 2.5 },
      { top: '58%', left: '85%', size: 2, dur: 4.1, delay: 0.6 },
      { top: '12%', left: '68%', size: 1.5, dur: 3.3, delay: 1.7 },
      { top: '42%', left: '22%', size: 2, dur: 5.0, delay: 1.4 },
    ].map((p, i) => (
      <motion.div
        key={i}
        animate={{ opacity: [0, 1, 0], y: [0, -20, 0] }}
        transition={{ duration: p.dur, repeat: Infinity, delay: p.delay, ease: 'easeInOut' }}
        className="absolute rounded-full pointer-events-none"
        style={{
          top: p.top, left: p.left,
          width: p.size, height: p.size,
          backgroundColor: '#00e87b',
          boxShadow: `0 0 ${p.size * 4}px ${p.size * 2}px rgba(0,232,123,0.6)`,
        }}
      />
    ))}

    <div className="relative max-w-5xl mx-auto px-6 text-center">
      <motion.div variants={stagger} initial="hidden" animate="show">
        <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-brand-primary/25 bg-brand-primary/[0.06] text-sm text-neutral-400 mb-8 glow-green">
          <span className="w-1.5 h-1.5 rounded-full bg-brand-primary animate-pulse" />
          Now with AI-Powered Threat Analysis
        </motion.div>
        <motion.h1 variants={fadeUp} className="text-5xl md:text-7xl font-bold tracking-tight leading-[1.1] mb-6"
          style={{ background: 'linear-gradient(135deg, #ffffff 0%, #00e87b 50%, #ffffff 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
          Give your security<br />the platform it deserves
        </motion.h1>
        <motion.p variants={fadeUp} className="text-lg md:text-xl text-neutral-400 max-w-2xl mx-auto mb-10 leading-relaxed">
          Cameleon automates incident response, routes threats to the right teams, and keeps you compliant with <span className="text-brand-primary/80 font-medium">ISO 27035</span> and <span className="text-brand-primary/80 font-medium">Algerian Law 18-07</span>.
        </motion.p>
        <motion.div variants={fadeUp} className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <a href="#roles" className="group flex items-center gap-2 bg-brand-primary text-black font-semibold px-8 py-3.5 rounded-xl hover:bg-brand-secondary transition-all glow-green-strong">
            Get Started Free <ArrowRight size={18} className="group-hover:translate-x-1 transition-transform" />
          </a>
          <a href="#features" className="flex items-center gap-2 border border-brand-primary/20 text-neutral-300 px-8 py-3.5 rounded-xl hover:bg-brand-primary/[0.06] hover:border-brand-primary/30 transition-all">
            See Features
          </a>
        </motion.div>
      </motion.div>
    </div>
  </section>
);


/* ─── Features ─── */
const features = [
  { icon: Zap, title: 'Automated Routing', desc: 'Incidents are automatically assigned to the right engineer based on severity and expertise.' },
  { icon: FileText, title: 'ISO-Aligned Workflows', desc: 'Pre-built response playbooks compliant with ISO 27035 and Algerian Law 18-07.' },
  { icon: Eye, title: 'Real-Time Monitoring', desc: 'Live dashboard with severity-coded alerts and instant notifications.' },
  { icon: Lock, title: 'Audit Trail', desc: 'Immutable logs of every action for full regulatory compliance and forensic review.' },
];

const Features = () => (
  <section id="features" className="py-24 px-6">
    <div className="max-w-6xl mx-auto">
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="text-center mb-16">
        <motion.p variants={fadeUp} className="text-brand-primary text-sm font-medium mb-3 tracking-wide uppercase">Features</motion.p>
        <motion.h2 variants={fadeUp} className="text-4xl md:text-5xl font-bold text-gradient tracking-tight">Everything you need.<br />Nothing you don't.</motion.h2>
      </motion.div>
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {features.map((f, i) => (
          <motion.div key={i} variants={fadeUp} className="group p-8 rounded-2xl border border-brand-border bg-brand-bg-card/40 hover:border-brand-primary/30 hover:bg-brand-bg-card/70 transition-all duration-300">
            <div className="w-12 h-12 rounded-xl bg-brand-primary-dim flex items-center justify-center mb-5 group-hover:glow-green transition-shadow">
              <f.icon className="text-brand-primary" size={22} />
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">{f.title}</h3>
            <p className="text-neutral-400 leading-relaxed">{f.desc}</p>
          </motion.div>
        ))}
      </motion.div>
    </div>
  </section>
);



/* ─── Pricing ─── */
const plans = [
  { name: 'Starter', price: 'Free', desc: 'For small teams getting started.', features: ['5 Incidents/month', 'Basic Workflows', 'Email Notifications', '1 User'], cta: 'Start Free', highlight: false },
  { name: 'Pro', price: '$49', desc: 'For growing security teams.', features: ['Unlimited Incidents', 'AI SOC Analysis', 'Priority Support', '10 Users', 'Pentester Module'], cta: 'Get Started', highlight: true },
  { name: 'Enterprise', price: 'Custom', desc: 'For large organizations.', features: ['Everything in Pro', 'On-Premise Deploy', 'Dedicated CSM', 'Unlimited Users', 'Custom Integrations', 'SLA Guarantee'], cta: 'Contact Sales', highlight: false },
];

const Pricing = () => (
  <section id="pricing" className="py-24 px-6">
    <div className="max-w-6xl mx-auto">
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="text-center mb-16">
        <motion.p variants={fadeUp} className="text-brand-primary text-sm font-medium mb-3 tracking-wide uppercase">Pricing</motion.p>
        <motion.h2 variants={fadeUp} className="text-4xl md:text-5xl font-bold text-gradient tracking-tight">Simple, transparent pricing</motion.h2>
      </motion.div>
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((p, i) => (
          <motion.div key={i} variants={fadeUp} className={`p-8 rounded-2xl border transition-all duration-300 flex flex-col ${p.highlight ? 'border-brand-primary/40 bg-brand-bg-card glow-green relative' : 'border-brand-border bg-brand-bg-card/40 hover:border-brand-border-bright'}`}>
            {p.highlight && <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-brand-primary text-black text-xs font-bold rounded-full">Recommended</div>}
            <h3 className="text-xl font-semibold text-white">{p.name}</h3>
            <div className="mt-4 mb-2"><span className="text-4xl font-bold text-white">{p.price}</span>{p.price !== 'Free' && p.price !== 'Custom' && <span className="text-neutral-500 text-sm">/month</span>}</div>
            <p className="text-neutral-400 text-sm mb-6">{p.desc}</p>
            <ul className="space-y-3 mb-8 flex-1">
              {p.features.map((f, j) => <li key={j} className="flex items-center gap-2 text-sm text-neutral-300"><CheckCircle size={16} className="text-brand-primary shrink-0" />{f}</li>)}
            </ul>
            <a href="#roles" className={`w-full py-3 rounded-xl font-medium text-center block transition-colors ${p.highlight ? 'bg-brand-primary text-black hover:bg-brand-secondary' : 'border border-brand-border-bright text-white hover:bg-white/5'}`}>{p.cta}</a>
          </motion.div>
        ))}
      </motion.div>
    </div>
  </section>
);

/* ─── FAQ ─── */
const faqs = [
  { q: 'What is Cameleon?', a: 'Cameleon is a cybersecurity SaaS platform that automates incident response, provides ISO-aligned workflows, and ensures full regulatory compliance.' },
  { q: 'Is it compliant with Algerian Law 18-07?', a: 'Yes. All workflows and audit logs are designed to meet the requirements of Law 18-07 and ISO 27035.' },
  { q: 'Can I integrate with my existing tools?', a: 'Cameleon provides a REST API and webhook support, making it easy to integrate with SIEMs, ticketing systems, and communication tools.' },
  { q: 'How does the pentester module work?', a: 'Engineers can grant time-limited, permission-scoped access to external pentesters. All actions are fully audited.' },
];

const FAQ = () => {
  const [openIdx, setOpenIdx] = useState(null);
  return (
    <section id="faq" className="py-24 px-6">
      <div className="max-w-3xl mx-auto">
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="text-center mb-16">
          <motion.p variants={fadeUp} className="text-brand-primary text-sm font-medium mb-3 tracking-wide uppercase">FAQ</motion.p>
          <motion.h2 variants={fadeUp} className="text-4xl font-bold text-gradient tracking-tight">Questions and Answers</motion.h2>
        </motion.div>
        <div className="space-y-3">
          {faqs.map((f, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.05 }} className="border border-brand-border rounded-xl overflow-hidden bg-brand-bg-card/40">
              <button onClick={() => setOpenIdx(openIdx === i ? null : i)} className="w-full flex items-center justify-between p-5 text-left hover:bg-white/[0.02] transition-colors">
                <span className="text-white font-medium">{f.q}</span>
                <ChevronDown size={18} className={`text-neutral-500 transition-transform ${openIdx === i ? 'rotate-180' : ''}`} />
              </button>
              <AnimatePresence>{openIdx === i && (
                <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.3 }}>
                  <p className="px-5 pb-5 text-neutral-400 leading-relaxed">{f.a}</p>
                </motion.div>
              )}</AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

/* ─── Roles CTA ─── */
const roles = [
  { id: 'engineer', title: 'IT / CS Engineer', desc: 'Monitor incidents, execute workflows, manage response.', icon: Cpu, path: '/engineer/dashboard', available: true },
  { id: 'admin', title: 'CEO / Director', desc: 'Executive overview, risk posture, compliance reports.', icon: BarChart3, path: '/admin/dashboard', available: true },
  { id: 'legal', title: 'Legal / Juridical', desc: 'Regulatory compliance, legal documentation, audit.', icon: FileText, path: '/legal/dashboard', available: true },
];

const RoleSelection = () => (
  <section id="roles" className="py-24 px-6 bg-radial-glow">
    <div className="max-w-4xl mx-auto text-center">
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger}>
        <motion.h2 variants={fadeUp} className="text-4xl md:text-5xl font-bold text-gradient tracking-tight mb-4">Start building, today.</motion.h2>
        <motion.p variants={fadeUp} className="text-neutral-400 text-lg mb-12">Select your role to access your workspace.</motion.p>
      </motion.div>
      <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={stagger} className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {roles.map(r => (
          <motion.a key={r.id} variants={fadeUp} href={r.path} className="group p-8 rounded-2xl border text-left transition-all duration-300 block border-brand-border hover:border-brand-primary/40 hover:glow-green bg-brand-bg-card/40 cursor-pointer hover:scale-[1.02] hover:shadow-lg">
            <div className="w-12 h-12 rounded-xl bg-brand-primary-dim flex items-center justify-center mb-5 group-hover:bg-brand-primary/20 transition-colors">
              <r.icon className="text-brand-primary" size={22} />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">{r.title}</h3>
            <p className="text-neutral-400 text-sm mb-4 leading-relaxed">{r.desc}</p>
            <span className="text-sm font-medium text-brand-primary group-hover:underline">
              Access Workspace →
            </span>
          </motion.a>
        ))}
      </motion.div>
    </div>
  </section>
);

/* ─── Footer ─── */
const Footer = () => (
  <footer className="bg-[#020202] border-t border-brand-primary/30 shadow-[0_-10px_50px_rgba(0,232,123,0.08)] py-6 px-6 relative z-10">
    <div className="max-w-6xl mx-auto flex flex-col items-center gap-6">
      <img src="/image/logo.png" alt="Cameleon Logo" className="w-42 h-42 object-contain" />
      <nav className="flex items-center gap-6">
        {[
          { label: 'Features', href: '#features' },
          { label: 'Pricing', href: '#pricing' },
          { label: 'FAQ', href: '#faq' },
          { label: 'Get Started', href: '#roles' },
        ].map(link => (
          <a key={link.label} href={link.href} className="text-sm text-neutral-500 hover:text-white transition-colors">{link.label}</a>
        ))}
      </nav>
      <div className="w-full pt-6 border-t border-brand-border text-center">
        <p className="text-xs text-neutral-600">© 2026 Cameleon. All rights reserved.</p>
      </div>
    </div>
  </footer>
);

/* ─── Landing Page ─── */
export const Landing = () => (
  <div className="min-h-screen bg-brand-bg-deep">
    <Navbar />
    <Hero />
    <Features />

    <Pricing />
    <FAQ />
    <RoleSelection />
    <Footer />
  </div>
);
