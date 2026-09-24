import React, { useState } from 'react';
import { 
  ShieldAlert, User, Clock, ExternalLink, Activity, Target, 
  Info, ShieldCheck, ChevronRight, FileText, LayoutList, AlertTriangle
} from 'lucide-react';

const augmentComplianceData = (originalData: any) => {
  if (!originalData) return null;
  const data = JSON.parse(JSON.stringify(originalData));
  
  // Removed hardcoded pending statuses to use live backend data
  // REMEDIATION BACKLOG (now built from live backend data)
  const backlog: any[] = [];
  ['nist_csf_functions', 'iso_27001_controls', 'rbi_framework', 'sebi_cscrf'].forEach(fwKey => {
    if(data[fwKey]) {
      Object.entries(data[fwKey]).forEach(([key, val]: [string, any]) => {
        if (val.extended && (val.extended.remediationStatus === 'Open' || val.extended.remediationStatus === 'In Progress')) {
          backlog.push({
            id: key,
            framework: fwKey === 'nist_csf_functions' ? 'NIST CSF 2.0' : fwKey === 'iso_27001_controls' ? 'ISO 27001:2022' : fwKey === 'rbi_framework' ? 'RBI Master Directions' : 'SEBI CSCRF',
            ownerRole: val.extended.ownerRole,
            treatmentDecision: val.extended.treatmentDecision,
            status: val.extended.remediationStatus,
            dueDate: val.extended.targetRemediationDate,
            riskUsd: val.risk_exposure_usd || 0
          });
        }
      });
    }
  });

  backlog.sort((a, b) => {
    if (b.riskUsd !== a.riskUsd) return b.riskUsd - a.riskUsd;
    return new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime();
  });
  data.backlog = backlog;

  return data;
};

const getMaturityLabel = (level: number) => {
  const map: Record<number, string> = { 0: 'Not Implemented', 1: 'Initial', 2: 'Developing', 3: 'Defined', 4: 'Managed', 5: 'Optimized' };
  return map[level] || 'Unknown';
};

const getMaturityColor = (level: number) => {
  const map: Record<number, string> = { 0: 'bg-zinc-800 text-zinc-400', 1: 'bg-rose-500/20 text-rose-300', 2: 'bg-amber-500/20 text-amber-300', 3: 'bg-yellow-500/20 text-yellow-300', 4: 'bg-emerald-500/20 text-emerald-300', 5: 'bg-indigo-500/20 text-indigo-300' };
  return map[level] || 'bg-zinc-800 text-zinc-400';
};

export default function ComplianceGapModule({ complianceData: rawData, loadingCompliance, fetchComplianceGap, formatCurrency }: any) {
  const [viewMode, setViewMode] = useState<'executive' | 'owner' | 'auditor' | 'backlog'>('executive');
  
  const complianceData = augmentComplianceData(rawData);

  if (!complianceData) {
    return (
      <div className="p-6 md:p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-medium text-white flex items-center gap-2">
              <ShieldCheck className="w-6 h-6 text-indigo-400" /> Compliance Gap Analysis
            </h2>
            <p className="text-sm text-zinc-400 mt-1">Multi-framework control coverage assessment.</p>
          </div>
          <button onClick={fetchComplianceGap} disabled={loadingCompliance}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs flex items-center gap-2 transition-colors">
            {loadingCompliance ? <><div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Analyzing...</> : 'Run Gap Analysis'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 md:p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-medium text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-indigo-400" /> Compliance Gap Analysis
          </h2>
          <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-zinc-400">
            <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> Last assessed: {new Date().toLocaleDateString()}</span>
            <span className="flex items-center gap-1.5"><Target className="w-3.5 h-3.5" /> Next scheduled review: {new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toLocaleDateString()}</span>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-zinc-950 rounded-lg p-1 border border-zinc-800">
            {['executive', 'owner', 'auditor', 'backlog'].map((mode) => (
              <button key={mode}
                onClick={() => setViewMode(mode as any)} 
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize ${viewMode === mode ? 'bg-indigo-600 text-white' : 'text-zinc-400 hover:text-zinc-200'}`}
              >
                {mode === 'backlog' ? <span className="flex items-center gap-1"><LayoutList className="w-3 h-3"/> Backlog</span> : mode}
              </button>
            ))}
          </div>
          <button onClick={fetchComplianceGap} disabled={loadingCompliance}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs flex items-center gap-2">
            {loadingCompliance ? <><div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Analyzing...</> : 'Run Gap Analysis'}
          </button>
        </div>
      </div>

      {/* UPDATED METHODOLOGY BANNER (BACKEND-DRIVEN) */}
      <div className="p-3.5 bg-indigo-950/30 border border-indigo-500/20 rounded-xl flex items-start gap-3 text-xs text-indigo-300">
        <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <div>
          <strong className="text-white block mb-1">Methodology & Data Disclaimers (Backend-driven):</strong>
          <ul className="list-disc pl-4 space-y-0.5 opacity-80">
            <li><strong>REAL (Backend-driven):</strong> Base coverage %, gaps identified, controls addressed, findings mapped, risk $, Owner roles, Target Dates, Maturity levels (L0-L5), Treatment decisions, Remediation status, and Evidence arrays.</li>
            <li><strong>Maturity Adjustments:</strong> Unvalidated 100% scores (e.g., PROTECT) are evaluated by the backend and downgraded based on lack of evidence and mapped to realistic maturity boundaries.</li>
            <li><strong>Valuations Pending:</strong> Dollar figures remain flagged as <em>Illustrative</em> until SLE/ARO are supplied via API. RBI & SEBI libraries remain scaffolded.</li>
          </ul>
        </div>
      </div>

      {viewMode === 'backlog' ? (
        // BACKLOG VIEW
        <div>
          <h3 className="text-lg font-medium text-zinc-100 mb-4 flex items-center gap-2">
            <LayoutList className="w-5 h-5 text-indigo-400" /> Prioritized Remediation Backlog
          </h3>
          <div className="overflow-x-auto border border-zinc-800 rounded-xl bg-zinc-950/50">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-900 text-xs uppercase text-zinc-400 border-b border-zinc-800">
                <tr>
                  <th className="px-4 py-3">Control Family</th>
                  <th className="px-4 py-3">Framework</th>
                  <th className="px-4 py-3">Owner</th>
                  <th className="px-4 py-3">Treatment</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Target Date</th>
                  <th className="px-4 py-3 text-right">Risk Exposure</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {complianceData.backlog.map((item: any, idx: number) => (
                  <tr key={idx} className="hover:bg-zinc-800/50 transition-colors">
                    <td className="px-4 py-3 font-semibold text-zinc-200">{item.id}</td>
                    <td className="px-4 py-3 text-xs text-zinc-400">{item.framework}</td>
                    <td className="px-4 py-3 text-xs text-zinc-300 flex items-center gap-1.5"><User className="w-3 h-3 text-indigo-400" /> {item.ownerRole}</td>
                    <td className="px-4 py-3 text-xs font-mono text-zinc-300">{item.treatmentDecision}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={`flex items-center gap-1 ${item.status === 'In Progress' ? 'text-amber-400' : 'text-rose-400'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${item.status === 'In Progress' ? 'bg-amber-400 animate-pulse' : 'bg-rose-400'}`}></span>
                        {item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-400">{item.dueDate}</td>
                    <td className="px-4 py-3 text-right font-mono font-medium text-rose-400">{formatCurrency(item.riskUsd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        // SCORECARD VIEW (Executive | Owner | Auditor)
        <>
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 text-center p-6 rounded-xl bg-zinc-950 border border-zinc-800 flex flex-col items-center justify-center">
              <p className="text-xs text-zinc-400 uppercase tracking-wider mb-2">Overall Compliance Score</p>
              <p className={`text-6xl font-semibold ${complianceData.overall_compliance_score >= 70 ? 'text-emerald-400' : complianceData.overall_compliance_score >= 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                {complianceData.overall_compliance_score}%
              </p>
              <p className="text-sm text-zinc-400 mt-2">{complianceData.active_gaps_count} active gaps identified across all frameworks</p>
            </div>
            
            {viewMode !== 'executive' && (
              <div className="w-full md:w-1/3 p-5 rounded-xl bg-zinc-950 border border-zinc-800">
                <h4 className="text-sm font-medium text-zinc-200 mb-4">Risk Methodology (ALE)</h4>
                <div className="space-y-3 text-xs">
                  <div className="flex justify-between items-center border-b border-zinc-800 pb-2">
                    <span className="text-zinc-400">Total SLE (Single Loss Exp.)</span>
                    <span className="text-amber-200 font-mono italic">Illustrative</span>
                  </div>
                  <div className="flex justify-between items-center border-b border-zinc-800 pb-2">
                    <span className="text-zinc-400">Aggregated ARO</span>
                    <span className="text-amber-200 font-mono italic">Illustrative</span>
                  </div>
                  <div className="flex justify-between items-center pt-1">
                    <span className="text-zinc-300 font-medium">Total ALE (Risk)</span>
                    <span className="text-rose-400 font-mono font-semibold">
                      {formatCurrency(
                        Object.values(complianceData.nist_csf_functions).reduce((acc: any, val: any) => acc + (val.risk_exposure_usd || 0), 0)
                      )}
                      *
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* NIST CSF 2.0 */}
          <div>
            <h3 className="text-lg font-medium text-zinc-100 mb-4">NIST CSF 2.0</h3>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              {Object.entries(complianceData.nist_csf_functions).map(([func, data]: [string, any]) => {
                const ext = data.extended;
                const showBeforeAfter = viewMode === 'executive' && data.original_coverage_pct && data.original_coverage_pct !== data.coverage_pct;

                return (
                  <div key={func} className={`p-4 rounded-xl border relative overflow-hidden ${data.status === 'COMPLIANT' ? 'bg-emerald-950/10 border-emerald-500/20' : data.status === 'PARTIAL' ? 'bg-amber-950/10 border-amber-500/20' : 'bg-rose-950/10 border-rose-500/20'}`}>
                    
                    <p className="text-xs font-medium uppercase tracking-wider text-zinc-300 mb-2">{func}</p>
                    
                    {showBeforeAfter ? (
                      <div className="flex flex-col gap-1 mb-3 bg-zinc-950 p-2 rounded border border-zinc-800">
                        <div className="flex justify-between items-center text-[10px] text-zinc-500 uppercase font-bold">
                          <span>Legacy Score</span>
                          <span className="line-through">{data.original_coverage_pct}%</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] text-amber-500 uppercase font-bold flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" /> Audited Level
                          </span>
                          <span className="text-xl font-semibold text-amber-400">{data.coverage_pct}%</span>
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-end gap-2 mb-3">
                        <p className={`text-3xl font-semibold ${data.status === 'COMPLIANT' ? 'text-emerald-400' : data.status === 'PARTIAL' ? 'text-amber-400' : 'text-rose-400'}`}>
                          {data.coverage_pct}%
                        </p>
                        <div className="pb-1 text-[10px] uppercase font-bold text-zinc-500">{data.status}</div>
                      </div>
                    )}

                    <div className="space-y-1.5 text-xs mt-3">
                      <div className="flex justify-between text-zinc-400">
                        <span>Coverage</span>
                        <span className="text-zinc-200">{data.controls_addressed}/{data.total_controls}</span>
                      </div>
                      {viewMode !== 'executive' && ext && (
                        <div className="flex justify-between items-center mt-1">
                          <span className="text-zinc-400">Maturity</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${getMaturityColor(ext.maturityLevel)}`}>
                            L{ext.maturityLevel}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* ISO 27001 Controls (Unchanged layout from previous step) */}
          <div>
            <h3 className="text-lg font-medium text-zinc-100 mb-4">ISO 27001:2022 Annex A</h3>
            <div className="space-y-4">
              {Object.entries(complianceData.iso_27001_controls).map(([domain, data]: [string, any]) => {
                const ext = data.extended;
                return (
                  <div key={domain} className="bg-zinc-950 rounded-xl border border-zinc-800 overflow-hidden">
                    <div className="p-4 flex flex-col md:flex-row items-center gap-4">
                      <div className="w-full md:w-48 text-sm text-zinc-200 font-medium shrink-0">{domain}</div>
                      <div className="flex-1 w-full">
                        <div className="h-2 bg-zinc-900 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full transition-all duration-700 ${data.coverage_pct >= 80 ? 'bg-emerald-500' : data.coverage_pct >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`} style={{width: `${data.coverage_pct}%`}}></div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 shrink-0 w-full md:w-auto justify-between md:justify-end">
                        <div className="text-right font-mono text-sm font-medium text-zinc-100 w-12">{data.coverage_pct}%</div>
                        <div className="text-right text-xs text-zinc-400 w-12">{data.controls_addressed}/{data.total_controls}</div>
                        {ext && (
                          <span className={`w-24 text-center px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${getMaturityColor(ext.maturityLevel)} border border-current opacity-80`}>
                            L{ext.maturityLevel}: {getMaturityLabel(ext.maturityLevel)}
                          </span>
                        )}
                      </div>
                    </div>

                    {ext && viewMode !== 'executive' && (
                      <div className="bg-zinc-900/50 p-4 border-t border-zinc-800 grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="space-y-3">
                          <h5 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5"><User className="w-3 h-3" /> Accountability</h5>
                          <div className="text-sm">
                            <div className="flex justify-between border-b border-zinc-800/50 pb-1 mb-1"><span className="text-zinc-500">Owner</span><span className="text-zinc-200 font-medium">{ext.ownerRole}</span></div>
                            <div className="flex justify-between"><span className="text-zinc-500">Target Date</span><span className="text-zinc-300 flex items-center gap-1"><Clock className="w-3 h-3 text-indigo-400" /> {ext.targetRemediationDate}</span></div>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <h5 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5"><Activity className="w-3 h-3" /> Workflow</h5>
                          <div className="text-sm">
                            <div className="flex justify-between border-b border-zinc-800/50 pb-1 mb-1"><span className="text-zinc-500">Treatment</span><span className="text-indigo-300 font-medium">{ext.treatmentDecision}</span></div>
                            <div className="flex justify-between"><span className="text-zinc-500">Status</span><span className="text-amber-300 flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span> {ext.remediationStatus}</span></div>
                          </div>
                        </div>
                        <div className="space-y-3">
                          <h5 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5"><FileText className="w-3 h-3" /> Evidence</h5>
                          {viewMode === 'auditor' ? (
                            <div className="space-y-2">
                              {ext.evidence.length === 0 ? (
                                <div className="text-xs text-rose-400 font-medium border border-rose-500/20 bg-rose-500/10 p-2 rounded">No Evidence Provided</div>
                              ) : (
                                ext.evidence.map((ev: any, i: number) => (
                                  <div key={i} className="text-xs bg-zinc-950 p-2 rounded border border-zinc-800 flex justify-between items-center group hover:border-indigo-500/50 transition-colors">
                                    <div><div className="text-zinc-300 font-medium flex items-center gap-1">{ev.type} <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 text-indigo-400 cursor-pointer" /></div><div className="text-zinc-500 text-[10px] mt-0.5">{ev.reviewer} • {ev.dateCollected}</div></div>
                                  </div>
                                ))
                              )}
                            </div>
                          ) : (
                            <div className="text-sm">
                              <div className="flex justify-between border-b border-zinc-800/50 pb-1 mb-1"><span className="text-zinc-500">Count</span><span className="text-zinc-200">{ext.evidence.length} Linked</span></div>
                              <div className="flex justify-between items-center pt-1"><span className="text-zinc-500 text-xs">Risk (ALE)</span><span className="text-rose-400 font-mono text-xs italic">Illustrative</span></div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          
          {/* RBI Framework */}
          <div>
            <h3 className="text-lg font-medium text-zinc-100 mb-4 mt-6">RBI Master Directions</h3>
            <div className="space-y-4">
              {Object.entries(complianceData.rbi_framework || {}).map(([domain, data]: [string, any]) => {
                if(data.status === "PENDING_MAPPING") return null;
                const ext = data.extended;
                return (
                  <div key={domain} className="bg-zinc-950 rounded-xl border border-zinc-800 overflow-hidden">
                    <div className="p-4 flex flex-col md:flex-row items-center gap-4">
                      <div className="w-full md:w-48 text-sm text-zinc-200 font-medium shrink-0">{domain}</div>
                      <div className="flex-1 w-full">
                        <div className="h-2 bg-zinc-900 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full transition-all duration-700 ${data.coverage_pct >= 80 ? 'bg-emerald-500' : data.coverage_pct >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`} style={{width: `${data.coverage_pct}%`}}></div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 shrink-0 w-full md:w-auto justify-between md:justify-end">
                        <div className="text-right font-mono text-sm font-medium text-zinc-100 w-12">{data.coverage_pct}%</div>
                        <div className="text-right text-xs text-zinc-400 w-12">{data.controls_addressed}/{data.total_controls}</div>
                        {ext && (
                          <span className={`w-24 text-center px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${getMaturityColor(ext.maturityLevel)} border border-current opacity-80`}>
                            L{ext.maturityLevel}: {getMaturityLabel(ext.maturityLevel)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* SEBI CSCRF */}
          <div>
            <h3 className="text-lg font-medium text-zinc-100 mb-4 mt-6">SEBI Cyber Resilience Framework</h3>
            <div className="space-y-4">
              {Object.entries(complianceData.sebi_cscrf || {}).map(([domain, data]: [string, any]) => {
                if(data.status === "PENDING_MAPPING") return null;
                const ext = data.extended;
                return (
                  <div key={domain} className="bg-zinc-950 rounded-xl border border-zinc-800 overflow-hidden">
                    <div className="p-4 flex flex-col md:flex-row items-center gap-4">
                      <div className="w-full md:w-48 text-sm text-zinc-200 font-medium shrink-0">{domain}</div>
                      <div className="flex-1 w-full">
                        <div className="h-2 bg-zinc-900 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full transition-all duration-700 ${data.coverage_pct >= 80 ? 'bg-emerald-500' : data.coverage_pct >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`} style={{width: `${data.coverage_pct}%`}}></div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 shrink-0 w-full md:w-auto justify-between md:justify-end">
                        <div className="text-right font-mono text-sm font-medium text-zinc-100 w-12">{data.coverage_pct}%</div>
                        <div className="text-right text-xs text-zinc-400 w-12">{data.controls_addressed}/{data.total_controls}</div>
                        {ext && (
                          <span className={`w-24 text-center px-2 py-0.5 rounded text-[10px] font-bold tracking-wider ${getMaturityColor(ext.maturityLevel)} border border-current opacity-80`}>
                            L{ext.maturityLevel}: {getMaturityLabel(ext.maturityLevel)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
