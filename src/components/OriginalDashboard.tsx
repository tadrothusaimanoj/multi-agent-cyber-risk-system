// @ts-nocheck
"use client";

import React, { useState, useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';
import { Brain, MessageSquare, Search, Scale, Database, RefreshCw, Zap } from 'lucide-react';
import ComplianceGapModule from './ComplianceGapModule';
import ReactMarkdown from 'react-markdown';



    // Professional Financial and Metric Formatters (US Dollar $)
    function formatCurrency(val) {
      if (val === undefined || val === null || isNaN(val)) return '$0';
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
        maximumFractionDigits: 0,
        minimumFractionDigits: 0
      }).format(val);
    }

    function formatCompactCurrency(val) {
      if (val === undefined || val === null || isNaN(val)) return '$0';
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD',
        notation: 'compact',
        maximumFractionDigits: 1
      }).format(val);
    }

    function formatNumber(val, decimals = 0) {
      if (val === undefined || val === null || isNaN(val)) return '0';
      return new Intl.NumberFormat('en-US', {
        maximumFractionDigits: decimals,
        minimumFractionDigits: decimals
      }).format(val);
    }

    function formatPercent(val, decimals = 1) {
      if (val === undefined || val === null || isNaN(val)) return '0.0%';
      return `${Number(val).toFixed(decimals)}%`;
    }

    function App() {
      // Core Data States
      const [summary, setSummary] = useState(null);
      const [optResult, setOptResult] = useState(null);
      const [frontierData, setFrontierData] = useState(null);
      const [findings, setFindings] = useState([]);
      const [execSummaryData, setExecSummaryData] = useState(null);

      // UI Control States
      const [budget, setBudget] = useState(50000);
      const [budgetInput, setBudgetInput] = useState("50000");
      const [strategy, setStrategy] = useState("pulp");
      const [activeTab, setActiveTab] = useState("dashboard"); // dashboard, findings, ingest, report
      
      // Findings Filter States
      const [severityFilter, setSeverityFilter] = useState("all");
      const [statusFilter, setStatusFilter] = useState("open");
      const [searchTerm, setSearchTerm] = useState("");

      // Loading States
      const [loadingSummary, setLoadingSummary] = useState(false);
      const [loadingOpt, setLoadingOpt] = useState(false);
      const [loadingFindings, setLoadingFindings] = useState(false);
      const [loadingIngestPass1, setLoadingIngestPass1] = useState(false);
      const [loadingIngestPass2, setLoadingIngestPass2] = useState(false);
      const [loadingReport, setLoadingReport] = useState(false);

      // Toast Notifications
      const [toast, setToast] = useState(null);
      const [copied, setCopied] = useState(false);

      // Chart references
      const buChartRef = useRef(null);
      const catChartRef = useRef(null);
      const buChartInst = useRef(null);
      const catChartInst = useRef(null);
      const paretoChartRef = useRef(null);
      const paretoChartInst = useRef(null);
      const [controlFilter, setControlFilter] = useState('all'); // 'all', 'selected', 'deferred'
      const [manualOverrides, setManualOverrides] = useState({}); // { [action_id]: boolean }
      const [advisorPersona, setAdvisorPersona] = useState('board'); // 'board' | 'cfo' | 'ciso'
      const fairBandChartRef = useRef(null);
      const fairBandChartInst = useRef(null);
      const scenarioBandChartRef = useRef(null);
      const scenarioBandChartInst = useRef(null);

      // ==========================================
      // GRC TOOL STATES
      // ==========================================

      // Risk Calculator States
      const [riskCalcInputs, setRiskCalcInputs] = useState({
        cve_id: '',
        threat_event_frequency: 12,
        vulnerability_score: 0.75,
        primary_loss_usd: 150000,
        secondary_loss_usd: 350000,
        control_effectiveness_pct: 85,
        risk_appetite_threshold_usd: 100000
      });
      const [riskCalcResult, setRiskCalcResult] = useState(null);
      const [loadingRiskCalc, setLoadingRiskCalc] = useState(false);
      const [riskCalcChartMode, setRiskCalcChartMode] = useState('band'); // 'band' (range whisker/violin) or 'pdf' (distribution curve)

      // Compliance Gap States
      const [complianceData, setComplianceData] = useState(null);
      const [loadingCompliance, setLoadingCompliance] = useState(false);

      // Audit Trail States
      const [auditLogs, setAuditLogs] = useState([]);
      const [loadingAudit, setLoadingAudit] = useState(false);
      const [auditForm, setAuditForm] = useState({
        action_type: 'RISK_ACCEPTED',
        actor: 'GRC Analyst',
        details: '',
        framework_ref: 'NIST CSF 2.0',
        impact_usd: 0
      });
      const [auditFilterType, setAuditFilterType] = useState('all');

      // Policy Mapper States
      const [policyText, setPolicyText] = useState('');
      const [policyResult, setPolicyResult] = useState(null);
      const [loadingPolicy, setLoadingPolicy] = useState(false);

      // Scenario Analysis States
      const [scenarios, setScenarios] = useState([
        { name: 'Conservative', budget: 25000 },
        { name: 'Moderate', budget: 50000 },
        { name: 'Aggressive', budget: 100000 }
      ]);
      const [scenarioResult, setScenarioResult] = useState(null);
      const [loadingScenarios, setLoadingScenarios] = useState(false);

      // Natural Language Query Agent States
      const [queryInput, setQueryInput] = useState('');
      const [loadingQuery, setLoadingQuery] = useState(false);
      const [activeCitation, setActiveCitation] = useState(null);
      const [chatMessages, setChatMessages] = useState([
        {
          sender: 'assistant',
          text: "Welcome to the Executive AI Risk Advisor. I operate in strictly read-only RAG mode, directly querying our continuous FAIR risk quantification model, vulnerability findings, candidate controls, and immutable audit logs. Ask any question about enterprise risk posture, drivers, or control effectiveness.",
          citations: [],
          provenance: { model_used: "TFIDF-Hybrid-RAG-v1 (Read-Only)", timestamp: new Date().toISOString() }
        }
      ]);

      const handleSendQuery = async (overrideQuery = null) => {
        const text = (overrideQuery || queryInput).trim();
        if (!text || loadingQuery) return;

        const userMsg = { sender: 'user', text };
        setChatMessages(prev => [...prev, userMsg]);
        setQueryInput('');
        setLoadingQuery(true);

        try {
          const res = await fetch('/query-agent', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({ query: text, max_citations: 5 })
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Query failed`);
          }

          const data = await res.json();
          setChatMessages(prev => [
            ...prev,
            {
              sender: 'assistant',
              text: data.answer,
              citations: data.citations || [],
              provenance: data.provenance,
              audit_log_id: data.audit_log_id
            }
          ]);
        } catch (e) {
          showToast(`Query Agent Error: ${e.message}`, "error");
          setChatMessages(prev => [
            ...prev,
            {
              sender: 'assistant',
              text: ` Query error: ${e.message}. Please ensure data ingestion has been run.`,
              citations: []
            }
          ]);
        } finally {
          setLoadingQuery(false);
        }
      };

      const showToast = (message, type = "info") => {
        setToast({ message, type, id: Date.now() });
        setTimeout(() => setToast(null), 4000);
      };

      // ==========================================
      // PHASE 4: Slide-Over Drill-Down Panel States
      // ==========================================
      const [slideoverOpen, setSlideoverOpen] = useState(false);
      const [slideoverType, setSlideoverType] = useState(null); // 'finding' | 'risk_calc'
      const [slideoverId, setSlideoverId] = useState(null);
      const [slideoverLoading, setSlideoverLoading] = useState(false);
      const [slideoverDetail, setSlideoverDetail] = useState(null);

      const handleOpenDrilldown = async (type, id, localFallback = null) => {
        setSlideoverType(type);
        setSlideoverId(id);
        setSlideoverOpen(true);
        setSlideoverLoading(true);
        setSlideoverDetail(null);

        try {
          let url = `/drilldown/${type}/${encodeURIComponent(id)}`;
          let options = { headers: { 'Accept': 'application/json' } };

          if (type === 'risk_calc' && riskCalcInputs) {
            url = '/drilldown/risk-calc';
            options = {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify(riskCalcInputs)
            };
          }

          const res = await fetch(url, options);
          if (res.ok) {
            const data = await res.json();
            setSlideoverDetail(data);
          } else {
            if (localFallback) {
              setSlideoverDetail({ entity_type: type, entity_id: id, fallback: localFallback });
            }
          }
        } catch (err) {
          console.error("Drilldown fetch error:", err);
          if (localFallback) {
            setSlideoverDetail({ entity_type: type, entity_id: id, fallback: localFallback });
          }
        } finally {
          setSlideoverLoading(false);
        }
      };

      const handleCloseDrilldown = () => {
        setSlideoverOpen(false);
        setSlideoverDetail(null);
      };

      // ==========================================
      // ACTION 1: Get Risk Summary
      // ==========================================
      const fetchRiskSummary = async () => {
        try {
          setLoadingSummary(true);
          const res = await fetch('/risk-summary', {
            headers: { 'Accept': 'application/json' }
          });
          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Failed to load risk summary`);
          }
          const data = await res.json();
          setSummary(data);
        } catch (e) {
          showToast(`Risk Summary Error: ${e.message}`, "error");
        } finally {
          setLoadingSummary(false);
        }
      };

      // ==========================================
      // ACTION 2: Optimize Security Investments (POST /optimize)
      // ==========================================
      const handleOptimize = async (customBudget = budget, customStrategy = strategy, fetchFrontier = true) => {
        try {
          setLoadingOpt(true);
          // Sanitize payload strictly: ensure numeric budget > 0
          const safeBudget = Math.max(1000, Number(customBudget) || 50000);
          const payload = {
            budget: safeBudget,
            strategy: customStrategy.toLowerCase().includes("greedy") ? "greedy" : "pulp",
            min_roi_threshold: null,
            include_frontier: fetchFrontier
          };

          const res = await fetch('/optimize', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Optimization failed`);
          }

          const data = await res.json();
          setOptResult(data);
          if (data.pareto_frontier) {
            setFrontierData(data.pareto_frontier);
          }
          setManualOverrides({});
          showToast(`Optimal allocation computed: ${data.selected_actions.length} controls selected (${formatCurrency(data.total_cost_allocated)})`, "success");
        } catch (e) {
          showToast(`Optimization Error: ${e.message}`, "error");
        } finally {
          setLoadingOpt(false);
        }
      };

      const handleToggleControl = (actionId) => {
        if (!optResult) return;
        const allControls = optResult.ranked_controls || optResult.selected_actions || [];
        const target = allControls.find(c => c.action_id === actionId);
        if (!target) return;

        const currentSelected = manualOverrides[actionId] !== undefined ? manualOverrides[actionId] : target.is_selected;
        const newSelected = !currentSelected;

        const updatedOverrides = { ...manualOverrides, [actionId]: newSelected };
        setManualOverrides(updatedOverrides);

        let totalCost = 0;
        let totalReduction = 0;
        const selectedActions = [];

        const updatedRanked = allControls.map(c => {
          const isSel = updatedOverrides[c.action_id] !== undefined ? updatedOverrides[c.action_id] : c.is_selected;
          if (isSel) {
            totalCost += c.cost;
            totalReduction += c.risk_reduction_usd;
            selectedActions.push({ ...c, is_selected: true });
          }
          return { ...c, is_selected: isSel };
        });

        const safeBudget = Number(budget) || 50000;
        const utilization = safeBudget > 0 ? (totalCost / safeBudget * 100) : 0;
        const roi = totalCost > 0 ? (totalReduction / totalCost) : 0;

        setOptResult(prev => ({
          ...prev,
          total_cost_allocated: Math.round(totalCost * 100) / 100,
          total_risk_reduction: Math.round(totalReduction * 100) / 100,
          budget_utilization_pct: Math.round(utilization * 10) / 10,
          overall_roi: Math.round(roi * 100) / 100,
          selected_actions: selectedActions,
          ranked_controls: updatedRanked,
          is_manual_override: Object.keys(updatedOverrides).length > 0
        }));

        showToast(
          `${newSelected ? '✓ Selected' : '✕ Deferred'} ${actionId} (Manual Simulation Override)`,
          newSelected ? "success" : "info"
        );
      };

      const handleResetOverrides = () => {
        setManualOverrides({});
        handleOptimize();
        showToast("Reset to mathematically optimal PuLP Knapsack allocation", "info");
      };

      // ==========================================
      // ACTION 3: Ingest Data (Pass 1 & Pass 2 in Workflow)
      // ==========================================
      const handleIngestPass1 = async () => {
        try {
          setLoadingIngestPass1(true);
          // Pass 1: Ingest primary asset inventory and CVE signatures
          const payload = {
            reseed_synthetic: true,
            days_back: 30,
            asset_mapping: {}
          };

          const res = await fetch('/ingest', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Ingestion Pass 1 failed`);
          }

          const data = await res.json();
          showToast(`Pass 1 Ingestion Complete: ${data.assets_ingested} assets, ${data.findings_ingested} findings`, "success");
          await fetchRiskSummary();
          await fetchFindings();
        } catch (e) {
          showToast(`Ingestion Pass 1 Error: ${e.message}`, "error");
        } finally {
          setLoadingIngestPass1(false);
        }
      };

      const handleIngestPass2 = async () => {
        try {
          setLoadingIngestPass2(true);
          // Pass 2: Re-ingest / Sync context enrichment & threat intelligence feeds
          const payload = {
            reseed_synthetic: true,
            days_back: 60,
            asset_mapping: { "sync_mode": "threat_intelligence_enrichment" }
          };

          const res = await fetch('/ingest', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Ingestion Pass 2 failed`);
          }

          const data = await res.json();
          showToast(`Pass 2 Threat Intel Sync Complete: ${data.findings_ingested} findings updated`, "success");
          await fetchRiskSummary();
          await handleOptimize();
        } catch (e) {
          showToast(`Ingestion Pass 2 Error: ${e.message}`, "error");
        } finally {
          setLoadingIngestPass2(false);
        }
      };

      // ==========================================
      // ACTION 4: List Findings (GET /findings)
      // ==========================================
      const fetchFindings = async () => {
        try {
          setLoadingFindings(true);
          const params = new URLSearchParams();
          if (severityFilter && severityFilter !== "all") params.append("severity", severityFilter);
          if (statusFilter && statusFilter !== "all") params.append("status", statusFilter);
          if (searchTerm && searchTerm.trim()) params.append("search", searchTerm.trim());

          const url = `/findings${params.toString() ? '?' + params.toString() : ''}`;
          const res = await fetch(url, {
            headers: { 'Accept': 'application/json' }
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Failed to list findings`);
          }

          const data = await res.json();
          setFindings(data);
        } catch (e) {
          showToast(`Findings Query Error: ${e.message}`, "error");
        } finally {
          setLoadingFindings(false);
        }
      };

      // ==========================================
      // ACTION 5: Get Executive Summary Report (GET /executive-summary)
      // ==========================================
      const fetchExecutiveSummary = async (customBudget = budget) => {
        try {
          setLoadingReport(true);
          const safeBudget = Math.max(1000, Number(customBudget) || 50000);
          const res = await fetch(`/executive-summary?budget=${safeBudget}`, {
            headers: { 'Accept': 'application/json' }
          });

          if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}: Failed to generate executive summary`);
          }

          const data = await res.json();
          setExecSummaryData(data);
        } catch (e) {
          showToast(`Executive Report Error: ${e.message}`, "error");
        } finally {
          setLoadingReport(false);
        }
      };

      // ==========================================
      // GRC TOOL ACTIONS
      // ==========================================

      // ACTION 6: Risk Calculator
      const handleRiskCalc = async () => {
        try {
          setLoadingRiskCalc(true);
          const res = await fetch('/risk-calculator', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(riskCalcInputs)
          });
          if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Risk calculation failed'); }
          const data = await res.json();
          setRiskCalcResult(data);
          showToast(`FAIR Risk Analysis: Residual risk ${formatCurrency(data.residual_risk_usd)}`, data.exceeds_appetite ? "error" : "success");
        } catch (e) {
          showToast(`Risk Calculator Error: ${e.message}`, "error");
        } finally {
          setLoadingRiskCalc(false);
        }
      };

      // ACTION 7: Compliance Gap Analysis
      const fetchComplianceGap = async () => {
        try {
          setLoadingCompliance(true);
          const res = await fetch('/compliance-gap', { headers: { 'Accept': 'application/json' } });
          if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Compliance gap analysis failed'); }
          const data = await res.json();
          setComplianceData(data);
        } catch (e) {
          showToast(`Compliance Gap Error: ${e.message}`, "error");
        } finally {
          setLoadingCompliance(false);
        }
      };

      // ACTION 8: Audit Trail
      const fetchAuditLogs = async () => {
        try {
          setLoadingAudit(true);
          const params = new URLSearchParams();
          if (auditFilterType && auditFilterType !== 'all') params.append('action_type', auditFilterType);
          const res = await fetch(`/audit-trail${params.toString() ? '?' + params.toString() : ''}`, { headers: { 'Accept': 'application/json' } });
          if (!res.ok) throw new Error('Failed to fetch audit trail');
          const data = await res.json();
          setAuditLogs(data);
        } catch (e) {
          showToast(`Audit Trail Error: ${e.message}`, "error");
        } finally {
          setLoadingAudit(false);
        }
      };

      const createAuditEntry = async () => {
        if (!auditForm.details.trim()) { showToast('Decision details are required', 'error'); return; }
        try {
          setLoadingAudit(true);
          const res = await fetch('/audit-trail', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(auditForm)
          });
          if (!res.ok) throw new Error('Failed to create audit entry');
          showToast('Audit entry recorded successfully', 'success');
          setAuditForm({ ...auditForm, details: '', impact_usd: 0 });
          await fetchAuditLogs();
        } catch (e) {
          showToast(`Audit Entry Error: ${e.message}`, "error");
        } finally {
          setLoadingAudit(false);
        }
      };

      // ACTION 9: Policy Mapping
      const handlePolicyMapping = async () => {
        if (!policyText.trim() || policyText.trim().length < 10) { showToast('Please enter policy text (minimum 10 characters)', 'error'); return; }
        try {
          setLoadingPolicy(true);
          const res = await fetch('/policy-mapping', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ policy_text: policyText })
          });
          if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Policy mapping failed'); }
          const data = await res.json();
          setPolicyResult(data);
          showToast(`Mapped ${data.total_nist_controls_matched} NIST + ${data.total_iso_controls_matched} ISO controls`, "success");
        } catch (e) {
          showToast(`Policy Mapping Error: ${e.message}`, "error");
        } finally {
          setLoadingPolicy(false);
        }
      };

      // ACTION 10: Scenario Analysis
      const handleScenarioAnalysis = async () => {
        const validScenarios = scenarios.filter(s => s.name.trim() && s.budget > 0);
        if (validScenarios.length < 1) { showToast('Add at least 1 valid scenario', 'error'); return; }
        try {
          setLoadingScenarios(true);
          const res = await fetch('/scenario-analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ scenarios: validScenarios })
          });
          if (!res.ok) { const err = await res.json().catch(() => ({})); throw new Error(err.detail || 'Scenario analysis failed'); }
          const data = await res.json();
          setScenarioResult(data);
          showToast(`Compared ${data.scenarios.length} budget scenarios`, "success");
        } catch (e) {
          showToast(`Scenario Analysis Error: ${e.message}`, "error");
        } finally {
          setLoadingScenarios(false);
        }
      };

      const addScenario = () => {
        if (scenarios.length >= 10) return;
        setScenarios([...scenarios, { name: `Scenario ${scenarios.length + 1}`, budget: 50000 }]);
      };

      const removeScenario = (idx) => {
        if (scenarios.length <= 1) return;
        setScenarios(scenarios.filter((_, i) => i !== idx));
      };

      const updateScenario = (idx, field, value) => {
        const updated = [...scenarios];
        updated[idx] = { ...updated[idx], [field]: field === 'budget' ? Number(value) || 0 : value };
        setScenarios(updated);
      };

      // Initial Mount
      useEffect(() => {
        fetchRiskSummary();
        fetchFindings();
        fetchExecutiveSummary(budget);
      }, []);

      const strategyRef = useRef(strategy);

      // Re-run optimization on budget/strategy change with debounce
      useEffect(() => {
        const timer = setTimeout(() => {
          const fetchFrontier = strategy !== strategyRef.current || !frontierData;
          strategyRef.current = strategy;
          handleOptimize(budget, strategy, fetchFrontier);
          fetchExecutiveSummary(budget);
        }, 150);
        return () => clearTimeout(timer);
      }, [budget, strategy]);

      // Trigger findings query when filters change
      useEffect(() => {
        fetchFindings();
      }, [severityFilter, statusFilter, searchTerm]);

      // Render Charts
      useEffect(() => {
        if (!summary) return;

        // Business Unit Bar Chart
        if (buChartRef.current) {
          if (buChartInst.current) buChartInst.current.destroy();
          const labels = Object.keys(summary.risk_by_business_unit);
          const values = Object.values(summary.risk_by_business_unit);

          buChartInst.current = new Chart(buChartRef.current, {
            type: 'bar',
            data: {
              labels,
              datasets: [{
                data: values,
                backgroundColor: ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b'],
                borderRadius: 6
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: { label: (ctx) => ` Exposure: ${formatCurrency(ctx.raw)}` }
                }
              },
              scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                y: {
                  ticks: { color: '#94a3b8', callback: (val) => formatCompactCurrency(val) },
                  grid: { color: '#334155' }
                }
              }
            }
          });
        }

        // Asset Category Doughnut Chart
        if (catChartRef.current) {
          if (catChartInst.current) catChartInst.current.destroy();
          const labels = Object.keys(summary.risk_by_asset_category).map(l => l.toUpperCase());
          const values = Object.values(summary.risk_by_asset_category);

          catChartInst.current = new Chart(catChartRef.current, {
            type: 'doughnut',
            data: {
              labels,
              datasets: [{
                data: values,
                backgroundColor: ['#38bdf8', '#818cf8', '#c084fc', '#f472b6', '#fbbf24'],
                borderWidth: 0
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 10 } },
                tooltip: {
                  callbacks: { label: (ctx) => ` ${ctx.label}: ${formatCurrency(ctx.raw)}` }
                }
              }
            }
          });
        }
      }, [summary, activeTab]);

      // Pareto Frontier Optimization Chart Effect
      useEffect(() => {
        if (!optResult || !frontierData || !paretoChartRef.current) return;
        if (activeTab !== 'optimizer' && activeTab !== 'dashboard') return;
        if (paretoChartInst.current) paretoChartInst.current.destroy();

        const frontier = frontierData;

        // DEBUG FLAG: Dev-visible log for auditability
        const DEBUG_FRONTIER = true;
        if (DEBUG_FRONTIER) {
          console.groupCollapsed(`Pareto Frontier Audit Log (${optResult.strategy_used || 'Optimizer'})`);
          console.table(frontier.map(p => ({
            "Budget": p.budget,
            "Controls": p.controls_selected,
            "Risk Reduction": p.risk_reduction,
            "Algorithm": p.algorithm || 'pulp'
          })));
          console.groupEnd();
        }

        const currentPt = {
          x: optResult.total_cost_allocated,
          y: optResult.total_risk_reduction
        };
        const kneePt = frontier.find(p => p.is_knee_point);

        paretoChartInst.current = new Chart(paretoChartRef.current, {
          type: 'line',
          data: {
            datasets: [
              {
                label: 'Pareto Efficient Frontier (Optimal Risk Reduction Curve)',
                data: frontier.map(p => ({ x: p.cost, y: p.risk_reduction })),
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.14)',
                borderWidth: 2.5,
                fill: true,
                tension: 0.25,
                pointRadius: 4,
                pointBackgroundColor: '#06b6d4',
                pointHoverRadius: 6,
                order: 2
              },
              {
                type: 'scatter',
                label: `Current Budget Allocation (${formatCurrency(optResult.total_cost_allocated)})`,
                data: [currentPt],
                borderColor: '#f59e0b',
                backgroundColor: '#f59e0b',
                pointRadius: 9,
                pointHoverRadius: 12,
                pointBorderWidth: 3,
                pointBorderColor: '#ffffff',
                order: 0
              },
              ...(kneePt ? [{
                type: 'scatter',
                label: `Diminishing Returns Knee (${formatCurrency(kneePt.cost)})`,
                data: [{ x: kneePt.cost, y: kneePt.risk_reduction }],
                borderColor: '#a855f7',
                backgroundColor: '#a855f7',
                pointRadius: 7,
                pointHoverRadius: 9,
                pointBorderWidth: 2,
                pointBorderColor: '#ffffff',
                order: 1
              }] : [])
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'top',
                labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 11, weight: 'bold' } }
              },
              tooltip: {
                callbacks: {
                  label: (ctx) => {
                    const raw = ctx.raw;
                    return ` Investment: ${formatCurrency(raw.x)} → Risk Reduction: ${formatCurrency(raw.y)}`;
                  }
                }
              }
            },
            scales: {
              x: {
                type: 'linear',
                title: { display: true, text: 'Allocated Security Budget (USD)', color: '#94a3b8', font: { size: 11 } },
                ticks: { color: '#94a3b8', callback: (val) => formatCompactCurrency(val) },
                grid: { color: '#1e293b' }
              },
              y: {
                title: { display: true, text: 'Total Risk Reduction ΔALE (USD)', color: '#94a3b8', font: { size: 11 } },
                ticks: { color: '#94a3b8', callback: (val) => formatCompactCurrency(val) },
                grid: { color: '#1e293b' }
              }
            }
          }
        });
      }, [optResult, activeTab]);

      // FAIR Confidence-Banded Distribution Chart Effect
      useEffect(() => {
        if (!riskCalcResult || activeTab !== 'risk-calc' || !fairBandChartRef.current) return;
        if (fairBandChartInst.current) fairBandChartInst.current.destroy();

        if (riskCalcChartMode === 'band') {
          // Range-based Confidence Band (Whisker / Violin Style) configuration in Chart.js
          const inh = riskCalcResult.inherent_ale_band || {
            min: riskCalcResult.inherent_risk_usd * 0.7,
            p10: riskCalcResult.inherent_risk_usd * 0.85,
            p50: riskCalcResult.inherent_risk_usd,
            p90: riskCalcResult.inherent_risk_usd * 1.2,
            max: riskCalcResult.inherent_risk_usd * 1.5,
            mean: riskCalcResult.inherent_risk_usd
          };
          const res = riskCalcResult.residual_ale_band || {
            min: riskCalcResult.residual_risk_usd * 0.7,
            p10: riskCalcResult.residual_risk_usd * 0.85,
            p50: riskCalcResult.residual_risk_usd,
            p90: riskCalcResult.residual_risk_usd * 1.2,
            max: riskCalcResult.residual_risk_usd * 1.5,
            mean: riskCalcResult.residual_risk_usd
          };
          const red = riskCalcResult.reduction_band || {
            min: riskCalcResult.risk_reduction_usd * 0.7,
            p10: riskCalcResult.risk_reduction_usd * 0.85,
            p50: riskCalcResult.risk_reduction_usd,
            p90: riskCalcResult.risk_reduction_usd * 1.2,
            max: riskCalcResult.risk_reduction_usd * 1.5,
            mean: riskCalcResult.risk_reduction_usd
          };

          fairBandChartInst.current = new Chart(fairBandChartRef.current, {
            type: 'bar',
            data: {
              labels: ['Inherent Loss (ALE)', 'Residual Loss (ALE)', 'Risk Reduction (ΔALE)'],
              datasets: [
                {
                  label: 'Full Range Envelope (Min — Max)',
                  data: [
                    [inh.min, inh.max],
                    [res.min, res.max],
                    [red.min, red.max]
                  ],
                  backgroundColor: [
                    'rgba(244, 63, 94, 0.18)',
                    'rgba(16, 185, 129, 0.18)',
                    'rgba(56, 189, 248, 0.18)'
                  ],
                  borderColor: [
                    'rgba(244, 63, 94, 0.50)',
                    'rgba(16, 185, 129, 0.50)',
                    'rgba(56, 189, 248, 0.50)'
                  ],
                  borderWidth: 1,
                  barPercentage: 0.75,
                  order: 2
                },
                {
                  label: '80% Confidence Band (P10 — P90)',
                  data: [
                    [inh.p10, inh.p90],
                    [res.p10, res.p90],
                    [red.p10, red.p90]
                  ],
                  backgroundColor: [
                    'rgba(244, 63, 94, 0.65)',
                    'rgba(16, 185, 129, 0.65)',
                    'rgba(56, 189, 248, 0.65)'
                  ],
                  borderColor: [
                    '#f43f5e',
                    '#10b981',
                    '#38bdf8'
                  ],
                  borderWidth: 2,
                  borderRadius: 4,
                  barPercentage: 0.45,
                  order: 1
                },
                {
                  label: 'Likely Estimate (P50 Mode)',
                  data: [
                    [inh.p50 - Math.max(10, (inh.max - inh.min) * 0.005), inh.p50 + Math.max(10, (inh.max - inh.min) * 0.005)],
                    [res.p50 - Math.max(10, (res.max - res.min) * 0.005), res.p50 + Math.max(10, (res.max - res.min) * 0.005)],
                    [red.p50 - Math.max(10, (red.max - red.min) * 0.005), red.p50 + Math.max(10, (red.max - red.min) * 0.005)]
                  ],
                  backgroundColor: ['#ffffff', '#ffffff', '#ffffff'],
                  borderColor: ['#ffffff', '#ffffff', '#ffffff'],
                  borderWidth: 3,
                  borderRadius: 2,
                  barPercentage: 0.85,
                  order: 0
                }
              ]
            },
            options: {
              indexAxis: 'y',
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'top',
                  labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 11, weight: 'bold' } }
                },
                tooltip: {
                  callbacks: {
                    label: (ctx) => {
                      const idx = ctx.dataIndex;
                      const metric = idx === 0 ? inh : (idx === 1 ? res : red);
                      if (ctx.datasetIndex === 0) {
                        return ` Full Range: ${formatCurrency(metric.min)} – ${formatCurrency(metric.max)}`;
                      } else if (ctx.datasetIndex === 1) {
                        return ` 80% CI Band: ${formatCurrency(metric.p10)} – ${formatCurrency(metric.p90)}`;
                      } else {
                        return ` Likely (P50): ${formatCurrency(metric.p50)} | Mean: ${formatCurrency(metric.mean)}`;
                      }
                    }
                  }
                }
              },
              scales: {
                x: {
                  title: { display: true, text: 'Loss Exposure (USD)', color: '#94a3b8', font: { size: 11 } },
                  ticks: { color: '#94a3b8', callback: (val) => formatCompactCurrency(val) },
                  grid: { color: '#1e293b' }
                },
                y: {
                  ticks: { color: '#cbd5e1', font: { weight: 'bold' } },
                  grid: { display: false }
                }
              }
            }
          });
        } else {
          // Probability Density Distribution (KDE Curves)
          const bins = riskCalcResult.distribution_bins;
          if (!bins || !bins.labels) return;

          fairBandChartInst.current = new Chart(fairBandChartRef.current, {
            type: 'line',
            data: {
              labels: bins.labels,
              datasets: [
                {
                  label: 'Inherent Risk PDF (Before Controls)',
                  data: bins.inherent_density,
                  borderColor: '#f43f5e',
                  backgroundColor: 'rgba(244, 63, 94, 0.20)',
                  fill: true,
                  tension: 0.4,
                  pointRadius: 3,
                  pointBackgroundColor: '#f43f5e',
                  borderWidth: 2
                },
                {
                  label: 'Residual Risk PDF (After Controls)',
                  data: bins.residual_density,
                  borderColor: '#10b981',
                  backgroundColor: 'rgba(16, 185, 129, 0.25)',
                  fill: true,
                  tension: 0.4,
                  pointRadius: 3,
                  pointBackgroundColor: '#10b981',
                  borderWidth: 2
                }
              ]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'top',
                  labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 11, weight: 'bold' } }
                },
                tooltip: {
                  callbacks: {
                    label: (ctx) => ` ${ctx.dataset.label}: ${Number(ctx.raw).toFixed(1)}% probability mass`
                  }
                }
              },
              scales: {
                x: {
                  title: { display: true, text: 'Loss Magnitude / Annualized Loss (USD)', color: '#94a3b8', font: { size: 11 } },
                  ticks: { color: '#94a3b8' },
                  grid: { color: '#1e293b' }
                },
                y: {
                  title: { display: true, text: 'Probability Density (%)', color: '#94a3b8', font: { size: 11 } },
                  ticks: { color: '#94a3b8', callback: (val) => `${val}%` },
                  grid: { color: '#1e293b' }
                }
              }
            }
          });
        }
      }, [riskCalcResult, activeTab, riskCalcChartMode]);

      // Scenario Analysis Confidence Band Chart Effect
      useEffect(() => {
        if (!scenarioResult || activeTab !== 'scenarios' || !scenarioBandChartRef.current) return;
        if (scenarioBandChartInst.current) scenarioBandChartInst.current.destroy();

        const validScenarios = scenarioResult.scenarios.filter(s => !s.error);
        if (validScenarios.length === 0) return;

        scenarioBandChartInst.current = new Chart(scenarioBandChartRef.current, {
          type: 'bar',
          data: {
            labels: validScenarios.map(s => s.name),
            datasets: [
              {
                label: 'Residual ALE Full Range (Min — Max)',
                data: validScenarios.map(s => [
                  s.confidence_band?.min ?? (s.confidence_band?.p10 ? s.confidence_band.p10 * 0.8 : 0),
                  s.confidence_band?.max ?? (s.confidence_band?.p90 ? s.confidence_band.p90 * 1.25 : 0)
                ]),
                backgroundColor: 'rgba(6, 182, 212, 0.16)',
                borderColor: 'rgba(6, 182, 212, 0.40)',
                borderWidth: 1,
                barPercentage: 0.65,
                order: 3
              },
              {
                label: 'Residual ALE 80% CI Band (P10 — P90)',
                data: validScenarios.map(s => [
                  s.confidence_band?.p10 || 0,
                  s.confidence_band?.p90 || 0
                ]),
                backgroundColor: 'rgba(6, 182, 212, 0.58)',
                borderColor: '#06b6d4',
                borderWidth: 2,
                borderRadius: 4,
                barPercentage: 0.40,
                order: 2
              },
              {
                type: 'line',
                label: 'Likely Residual ALE (P50)',
                data: validScenarios.map(s => s.confidence_band?.p50 || 0),
                borderColor: '#38bdf8',
                backgroundColor: '#ffffff',
                pointBackgroundColor: '#ffffff',
                pointBorderColor: '#0284c7',
                pointBorderWidth: 2,
                pointRadius: 6,
                pointHoverRadius: 8,
                borderDash: [5, 5],
                borderWidth: 2,
                order: 1
              },
              {
                type: 'line',
                label: 'Total Risk Reduction (ΔALE)',
                data: validScenarios.map(s => s.total_risk_reduction || 0),
                borderColor: '#10b981',
                backgroundColor: '#10b981',
                pointRadius: 5,
                pointHoverRadius: 7,
                pointBackgroundColor: '#10b981',
                borderWidth: 2,
                order: 0
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'top',
                labels: { color: '#cbd5e1', boxWidth: 12, font: { size: 11, weight: 'bold' } }
              },
              tooltip: {
                callbacks: {
                  label: (ctx) => {
                    const s = validScenarios[ctx.dataIndex];
                    if (!s) return '';
                    if (ctx.datasetIndex === 0) {
                      return ` Full Range: ${formatCurrency(s.confidence_band?.min)} – ${formatCurrency(s.confidence_band?.max)}`;
                    } else if (ctx.datasetIndex === 1) {
                      return ` 80% CI Band: ${formatCurrency(s.confidence_band?.p10)} – ${formatCurrency(s.confidence_band?.p90)}`;
                    } else if (ctx.datasetIndex === 2) {
                      const lefP50 = s.confidence_band?.lef_band?.p50 !== undefined ? s.confidence_band.lef_band.p50.toFixed(2) : '—';
                      return ` Likely (P50): ${formatCurrency(s.confidence_band?.p50)} | LEF: ${lefP50}/yr`;
                    } else if (ctx.datasetIndex === 3) {
                      return ` Risk Reduction: ${formatCurrency(s.total_risk_reduction)}`;
                    }
                    return `${ctx.dataset.label}: ${ctx.raw}`;
                  }
                }
              }
            },
            scales: {
              x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
              y: {
                ticks: { color: '#94a3b8', callback: (val) => formatCompactCurrency(val) },
                grid: { color: '#1e293b' }
              }
            }
          }
        });
      }, [scenarioResult, activeTab]);

      return (
        <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
          {/* Toast Notification Banner */}
          {toast && (
            <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-xl shadow-lg border flex items-center gap-3 transition-all duration-300 ${
              toast.type === 'error' ? 'bg-rose-950/90 border-rose-500 text-rose-200' :
              toast.type === 'success' ? 'bg-emerald-950/90 border-emerald-500 text-emerald-200' :
              'bg-zinc-900/90 border-indigo-500 text-indigo-200'
            }`}>
              <div className={`w-2 h-2 rounded-full animate-ping ${
                toast.type === 'error' ? 'bg-rose-400' :
                toast.type === 'success' ? 'bg-emerald-400' :
                'bg-indigo-400'
              }`}></div>
              <span className="text-sm font-medium">{toast.message}</span>
            </div>
          )}

          {/* Header */}
          <header className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-zinc-800 pb-6 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-xl bg-indigo-600 text-white flex items-center justify-center text-white font-medium text-xl shadow-sm border border-zinc-800">
                CG
              </div>
              <div>
                <h1 className="text-3xl font-semibold text-transparent bg-clip-text text-zinc-100">
                  CyberGuard AI
                </h1>
                <p className="text-xs text-zinc-400 font-medium tracking-wide uppercase">
                  Continuous Cyber Risk Quantification & Investment Optimization Platform
                </p>
              </div>
            </div>

            {/* Ingestion Workflow Buttons (Action 2: Ingest Data called twice) */}
            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={handleIngestPass1}
                disabled={loadingIngestPass1}
                className="px-3.5 py-1.5 rounded-lg bg-zinc-800/50 hover:bg-zinc-800 border border-zinc-800 text-xs font-semibold text-indigo-300 flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                {loadingIngestPass1 ? <div className="w-3.5 h-3.5 border-2 border-indigo-500/50 border-t-transparent rounded-full animate-spin"></div> : <><Database className="w-3.5 h-3.5" /><span>Ingest Assets & CVEs</span></>}
              </button>
              <button
                onClick={handleIngestPass2}
                disabled={loadingIngestPass2}
                className="px-3.5 py-1.5 rounded-lg bg-zinc-800/50 hover:bg-zinc-800 border border-zinc-800 text-xs font-semibold text-purple-300 flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                {loadingIngestPass2 ? <div className="w-3.5 h-3.5 border-2 border-purple-400 border-t-transparent rounded-full animate-spin"></div> : <><RefreshCw className="w-3.5 h-3.5" /><span>Sync Threat Intel (Pass 2)</span></>}
              </button>
            </div>
          </header>

          {/* Navigation Tabs */}
          <nav className="flex flex-wrap gap-1 border-b border-zinc-800 pb-2">
            {[
              { id: 'dashboard', label: 'Executive Dashboard' },
              { id: 'optimizer', label: 'Security Investment Optimizer' },
              { id: 'findings', label: `Findings Explorer (${findings.length})` },
              { id: 'report', label: 'Board Executive Report' },
              { id: 'risk-calc', label: 'Risk Calculator' },
              { id: 'compliance', label: 'Compliance Gap' },
              { id: 'audit', label: 'Audit Trail' },
              { id: 'policy', label: 'Policy Mapper' },
              { id: 'scenarios', label: 'Scenario Analysis' }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all ${
                  activeTab === tab.id
                    ? 'bg-indigo-600 text-white text-zinc-950 shadow-md font-medium'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-900'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          {/* Tab 1: Executive Dashboard View */}
          {(activeTab === 'dashboard' || activeTab === 'optimizer') && (
            <div className="space-y-8">
              {/* Executive Headline Metric Cards */}
              <section className="grid grid-cols-1 md:grid-cols-4 gap-5">
                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md relative overflow-hidden">
                  <p className="text-xs font-semibold text-rose-300 uppercase tracking-wider mb-1">Total Quantified Risk</p>
                  <div className="text-3xl sm:text-4xl font-medium font-mono tracking-tight text-rose-400">
                    {formatCurrency(summary?.total_quantified_risk || 0)}
                  </div>
                  <p className="text-xs text-zinc-400 mt-2">Annualized dollar loss (Threat × Vuln × Asset Value)</p>
                </div>

                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md">
                  <p className="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-1">Assets Protected</p>
                  <div className="text-3xl sm:text-4xl font-medium font-mono text-zinc-100">{formatNumber(summary?.total_assets ?? 25)}</div>
                  <p className="text-xs text-zinc-400 mt-2">Enterprise Servers, DBs, Clusters & Gateways</p>
                </div>

                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md">
                  <p className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-1">Security Findings</p>
                  <div className="text-3xl sm:text-4xl font-medium font-mono text-zinc-100">
                    {formatNumber(summary?.total_findings ?? findings.length)}
                  </div>
                  <p className="text-xs text-zinc-400 mt-2">Prioritized with CVSS, EPSS & Scikit-Learn</p>
                </div>

                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md">
                  <p className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-1">Avg Risk per Asset</p>
                  <div className="text-3xl sm:text-4xl font-medium font-mono text-zinc-100">{formatCurrency(summary?.average_asset_risk || 0)}</div>
                  <p className="text-xs text-zinc-400 mt-2">FAIR calibrated Loss Magnitude</p>
                </div>
              </section>

              {/* ACTION 4: Dynamic Context-Aware Executive Risk Advisor */}
              <section className="p-6 md:p-8 rounded-xl bg-zinc-900/50 border border-zinc-800 shadow-lg space-y-5">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-indigo-500/10 text-indigo-400 border border-zinc-800 flex items-center justify-center text-indigo-300 font-medium text-xl">
                      <Brain className="w-5 h-5 text-indigo-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-xl font-medium text-white">Dynamic Executive Risk Advisor</h2>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-zinc-800">
                          {Object.keys(manualOverrides).length > 0 ? ' Manual Simulation' : 'PuLP Optimal'}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 mt-0.5">
                        Real-time, context-aware decision intelligence responding to budget shifts, control overrides, and live risk metrics.
                      </p>
                    </div>
                  </div>

                  {/* Persona Selector Tabs */}
                  <div className="flex items-center gap-1.5 bg-zinc-950 p-1.5 rounded-xl border border-zinc-800 text-xs">
                    <button
                      type="button"
                      onClick={() => setAdvisorPersona('board')}
                      className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                        advisorPersona === 'board' ? 'bg-indigo-600 text-white text-zinc-950 shadow-md font-medium' : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      Board & CEO
                    </button>
                    <button
                      type="button"
                      onClick={() => setAdvisorPersona('cfo')}
                      className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                        advisorPersona === 'cfo' ? 'bg-emerald-500 text-zinc-950 shadow-md font-medium' : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      CFO / Capital Efficiency
                    </button>
                    <button
                      type="button"
                      onClick={() => setAdvisorPersona('ciso')}
                      className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${
                        advisorPersona === 'ciso' ? 'bg-purple-500 text-zinc-950 shadow-md font-medium' : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      CISO / Threat Posture
                    </button>
                  </div>
                </div>

                {/* Over-Budget Alert Warning */}
                {optResult && optResult.total_cost_allocated > budget && (
                  <div className="p-3.5 bg-rose-950/40 border border-rose-500/50 rounded-xl flex items-center justify-between text-xs text-rose-300">
                    <div className="flex items-center gap-2">
                      <span className="text-base"></span>
                      <span>
                        <strong>Budget Overrun Detected:</strong> Manual selection total ({formatCurrency(optResult.total_cost_allocated)}) exceeds allocated budget ({formatCurrency(budget)}) by <strong className="text-white">{formatCurrency(optResult.total_cost_allocated - budget)}</strong>.
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={handleResetOverrides}
                      className="px-2.5 py-1 bg-rose-900/60 hover:bg-rose-800 border border-rose-500/40 rounded text-[11px] font-medium text-white transition-colors"
                    >
                      Reset to Optimal
                    </button>
                  </div>
                )}

                {/* Real-Time Advisor Narrative */}
                <div className="p-5 rounded-xl bg-zinc-950 border border-zinc-800 text-zinc-200 text-sm leading-relaxed space-y-3">
                  {advisorPersona === 'board' && (
                    <div>
                      <p>
                        CyberGuard AI quantifies current enterprise cyber risk exposure at <strong className="text-rose-400">{formatCurrency(summary?.total_quantified_risk || 0)}</strong> across <strong className="text-white">{summary?.total_assets || 25}</strong> monitored assets and <strong className="text-amber-300">{summary?.total_findings || findings.length}</strong> active findings.
                        {optResult && optResult.total_cost_allocated > 0 ? (
                          <span>
                            {' '}Allocating the current <strong className="text-indigo-300">{formatCurrency(budget)}</strong> budget executes <strong className="text-emerald-300">{optResult.selected_actions.length}</strong> targeted controls costing <strong className="text-white">{formatCurrency(optResult.total_cost_allocated)}</strong>, eliminating <strong className="text-emerald-400">{formatCurrency(optResult.total_risk_reduction)}</strong> in annualized cyber loss ({formatPercent((optResult.total_risk_reduction / (summary?.total_quantified_risk || 1)) * 100, 1)} of total risk) for a <strong className="text-amber-300">{optResult.overall_roi}x</strong> return on investment.
                          </span>
                        ) : (
                          <span> Continuous monitoring advises funding high-leverage controls to curtail potential financial liabilities.</span>
                        )}
                        {Object.keys(manualOverrides).length > 0 && (
                          <span className="block mt-2 text-xs text-amber-300 font-medium">
                             Notice: Executive briefing reflects {Object.keys(manualOverrides).length} custom manual control override(s) from standard PuLP optimization.
                          </span>
                        )}
                      </p>
                    </div>
                  )}

                  {advisorPersona === 'cfo' && (
                    <div className="space-y-2">
                      <p>
                        <strong>Financial & Capital Allocation Summary:</strong> Capital efficiency is operating at <strong className="text-emerald-400">{optResult?.overall_roi || 0}x ROI</strong>, generating <strong className="text-emerald-300">${Number(optResult?.overall_roi || 0).toFixed(2)}</strong> in risk reduction for every $1.00 deployed.
                      </p>
                      <p className="text-xs text-zinc-400">
                        • Budget Utilization: <strong className="text-indigo-300">{optResult?.budget_utilization_pct || 0}%</strong> ({formatCurrency(optResult?.total_cost_allocated || 0)} of {formatCurrency(budget)}).
                        {' '}• Unallocated Headroom: <strong className="text-zinc-200">{formatCurrency(Math.max(0, budget - (optResult?.total_cost_allocated || 0)))}</strong>.
                        {' '}• Net Risk Mitigated: <strong className="text-emerald-400">{formatCurrency(optResult?.total_risk_reduction || 0)}</strong>.
                        {' '}• Remaining Enterprise Exposure: <strong className="text-rose-400">{formatCurrency(Math.max(0, (summary?.total_quantified_risk || 0) - (optResult?.total_risk_reduction || 0)))}</strong>.
                      </p>
                    </div>
                  )}

                  {advisorPersona === 'ciso' && (
                    <div className="space-y-2">
                      <p>
                        <strong>Technical Security & Defense Posture:</strong> Active findings register spans <strong className="text-white">{summary?.total_findings || findings.length}</strong> items across all 4 severity tiers (Critical, High, Medium, Low).
                      </p>
                      <p className="text-xs text-zinc-400">
                        • Selected Controls Defense: <strong className="text-emerald-300">{optResult?.selected_actions.length || 0}</strong> remediations active across NIST CSF 2.0 functions (`PROTECT`, `DETECT`, `RESPOND`).
                        {' '}• High/Critical Exploit Probability Coverage: Primary focus on internet-facing infrastructure and remote execution vulnerabilities (Log4j, runc, Jenkins CLI).
                        {' '}• Status: {optResult?.total_cost_allocated > budget ? <span className="text-rose-400 font-medium">Deficit Warning — additional budget authorization needed.</span> : <span className="text-emerald-400 font-medium">Within authorized budgetary constraints.</span>}
                      </p>
                    </div>
                  )}
                </div>

                {/* Dynamic Real-Time KPI Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center font-mono">
                  <div className="p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                    <span className="text-[10px] text-zinc-400 uppercase block font-sans">Capital Deployed</span>
                    <span className="text-base font-medium text-indigo-300">{formatCurrency(optResult?.total_cost_allocated || 0)}</span>
                  </div>
                  <div className="p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                    <span className="text-[10px] text-zinc-400 uppercase block font-sans">Risk Eliminated (ΔALE)</span>
                    <span className="text-base font-medium text-emerald-400">{formatCurrency(optResult?.total_risk_reduction || 0)}</span>
                  </div>
                  <div className="p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                    <span className="text-[10px] text-zinc-400 uppercase block font-sans">Capital ROI</span>
                    <span className="text-base font-medium text-amber-300">{optResult?.overall_roi || 0}x</span>
                  </div>
                  <div className="p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                    <span className="text-[10px] text-zinc-400 uppercase block font-sans">Active Controls</span>
                    <span className="text-base font-medium text-white">{optResult?.selected_actions?.length || 0} Selected</span>
                  </div>
                </div>
              </section>

              {/* Natural Language Query Agent (Read-Only RAG Chat Panel) */}
              <section className="p-6 md:p-8 rounded-xl bg-zinc-900/50 border border-zinc-800 shadow-lg space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-indigo-500/10 text-indigo-400 border border-zinc-800 flex items-center justify-center text-indigo-300 text-xl font-medium">
                      <MessageSquare className="w-5 h-5 text-indigo-400" />
                    </div>
                    <div>
                      <h2 className="text-xl font-medium text-white flex items-center gap-2">
                        Executive AI Risk Advisor
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-indigo-950 border border-zinc-800 text-indigo-300">
                          RAG Grounded
                        </span>
                      </h2>
                      <p className="text-xs text-zinc-400 mt-0.5">
                        Ask natural language questions grounded in live findings, controls, FAIR risk quantification, and audit trail records.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2.5 py-1 rounded-lg flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                      Strictly Read-Only (0 Commits)
                    </span>
                  </div>
                </div>

                {/* Curated Suggested Queries */}
                <div className="space-y-1.5">
                  <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-semibold">Suggested Questions:</span>
                  <div className="flex flex-wrap gap-2">
                    {[
                      "What's driving our Q3 risk increase?",
                      "Which controls provide the highest ROI for our budget?",
                      "What critical vulnerabilities affect FinTech / Payments?",
                      "What recent actions were recorded in the audit trail?"
                    ].map((qText, qIdx) => (
                      <button
                        key={qIdx}
                        type="button"
                        onClick={() => handleSendQuery(qText)}
                        disabled={loadingQuery}
                        className="text-xs px-3 py-1.5 rounded-lg bg-zinc-800/50/80 hover:bg-zinc-800 text-indigo-300 border border-zinc-800 hover:border-zinc-800 transition-all text-left disabled:opacity-50"
                      >
                        🔍 {qText}
                      </button>
                    ))}
                  </div>
                </div>

                {/* 2-Column RAG Layout */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Left Column: Chat Area */}
                  <div className="lg:col-span-2 space-y-4">
                    {/* Chat Message Stream */}
                    <div className="space-y-4 max-h-96 overflow-y-auto pr-2 bg-zinc-950/60 p-4 rounded-xl border border-zinc-800">
                      {chatMessages.map((msg, mIdx) => (
                        <div key={mIdx} className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'} space-y-2`}>
                          <div className={`max-w-[90%] p-4 rounded-xl text-sm leading-relaxed ${
                            msg.sender === 'user'
                              ? 'bg-indigo-600 text-white hover:bg-indigo-500 text-white rounded-tr-none shadow-md'
                              : 'bg-zinc-900 border border-zinc-800/20 text-zinc-200 rounded-tl-none space-y-3'
                          }`}>
                            {msg.sender === 'assistant' && (
                              <div className="flex items-center justify-between gap-2 pb-2 border-b border-zinc-800 text-xs text-zinc-400">
                                <span className="font-semibold text-indigo-300 flex items-center gap-1.5">
                                  <span>🤖</span> CyberGuard AI Advisor
                                </span>
                                {msg.provenance && (
                                  <span className="font-mono text-[10px] text-zinc-400">
                                    {msg.provenance.model_used}
                                  </span>
                                )}
                              </div>
                            )}

                            <div className="prose prose-invert prose-sm max-w-none">
                              <ReactMarkdown>{msg.text}</ReactMarkdown>
                            </div>

                            {/* Citations Tray */}
                            {msg.citations && msg.citations.length > 0 && (
                              <div className="pt-3 border-t border-zinc-800/80 space-y-2">
                                <span className="text-[11px] font-semibold text-indigo-400 uppercase tracking-wider block">
                                  Source Records Cited ({msg.citations.length}):
                                </span>
                                <div className="flex flex-wrap gap-1.5">
                                  {msg.citations.map((cit, cIdx) => (
                                    <button
                                      key={cIdx}
                                      onClick={() => setActiveCitation(cit)}
                                      title="Click to view full record"
                                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800/50 text-xs border font-mono transition-all ${
                                        activeCitation?.id === cit.id 
                                          ? 'border-indigo-400 text-white shadow-[0_0_8px_rgba(99,102,241,0.3)]' 
                                          : 'border-zinc-800 text-zinc-200 hover:border-indigo-500/50'
                                      }`}
                                    >
                                      <span className={`w-1.5 h-1.5 rounded-full ${
                                        cit.type === 'finding' ? 'bg-rose-400' :
                                        cit.type === 'remediation' ? 'bg-emerald-400' :
                                        cit.type === 'asset' ? 'bg-indigo-400' : 'bg-purple-400'
                                      }`}></span>
                                      <strong className={activeCitation?.id === cit.id ? 'text-indigo-200' : 'text-indigo-300'}>{cit.id}</strong>
                                    </button>
                                  ))}
                                </div>
                              </div>
                            )}

                            {msg.audit_log_id && (
                              <div className="text-[10px] text-zinc-500 font-mono mt-2">
                                ✓ Audit Trail Log #{msg.audit_log_id} recorded
                              </div>
                            )}
                          </div>
                        </div>
                      ))}

                      {loadingQuery && (
                        <div className="flex items-center gap-3 text-indigo-400 text-sm p-3 bg-zinc-900/60 rounded-xl border border-zinc-800/20 animate-pulse">
                          <div className="w-4 h-4 border-2 border-indigo-500/50 border-t-transparent rounded-full animate-spin"></div>
                          <span>Retrieving live evidence from risk register, findings, and audit trail...</span>
                        </div>
                      )}
                    </div>
                    {/* Input Field & Submit */}
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        handleSendQuery();
                      }}
                      className="flex gap-2"
                    >
                      <input
                        type="text"
                        value={queryInput}
                        onChange={(e) => setQueryInput(e.target.value)}
                        placeholder="Ask a question (e.g., What's driving our Q3 risk increase?)..."
                        disabled={loadingQuery}
                        className="flex-1 bg-zinc-950 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 transition-colors"
                      />
                      <button
                        type="submit"
                        disabled={loadingQuery || !queryInput.trim()}
                        className="px-6 py-3 bg-indigo-600 text-white hover:bg-indigo-500  disabled:bg-zinc-900 text-zinc-950 disabled:text-zinc-500 font-medium rounded-xl text-sm transition-all flex items-center gap-2"
                      >
                        <span>Send</span>
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                        </svg>
                      </button>
                    </form>
                  </div>

                  {/* Right Column: Citation Detail Panel */}
                  <div className="lg:col-span-1 bg-zinc-950/80 border border-zinc-800 rounded-xl p-5 shadow-inner min-h-[300px] flex flex-col relative overflow-hidden">
                    <div className="flex items-center gap-2 border-b border-zinc-800 pb-3 mb-4">
                      <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      <h3 className="text-sm font-semibold text-zinc-200">Citation Inspector</h3>
                    </div>
                    
                    {activeCitation ? (
                      <div className="space-y-4 animate-in fade-in zoom-in-95 duration-200">
                        <div>
                          <span className="text-[10px] uppercase text-zinc-500 font-bold block mb-1">Record ID</span>
                          <span className="font-mono text-sm text-indigo-300 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">{activeCitation.id}</span>
                        </div>
                        <div>
                          <span className="text-[10px] uppercase text-zinc-500 font-bold block mb-1">Record Type</span>
                          <span className="capitalize text-xs font-medium text-zinc-300">{activeCitation.type.replace('_', ' ')}</span>
                        </div>
                        <div>
                          <span className="text-[10px] uppercase text-zinc-500 font-bold block mb-1">Title</span>
                          <span className="text-sm font-medium text-white leading-snug block">{activeCitation.title}</span>
                        </div>
                        {activeCitation.details && (
                          <div>
                            <span className="text-[10px] uppercase text-zinc-500 font-bold block mb-1">Extracted Details</span>
                            <div className="text-xs text-zinc-400 leading-relaxed bg-zinc-900 p-3 rounded-lg border border-zinc-800">
                              {activeCitation.details}
                            </div>
                          </div>
                        )}
                        <div>
                          <span className="text-[10px] uppercase text-zinc-500 font-bold block mb-1">Semantic Match Score</span>
                          <div className="w-full bg-zinc-800 rounded-full h-1.5 mt-1.5">
                            <div className="bg-indigo-500 h-1.5 rounded-full" style={{ width: `${Math.min(100, activeCitation.relevance_score * 100)}%` }}></div>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-500 mt-1 block">{(activeCitation.relevance_score * 100).toFixed(1)}% relevance</span>
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 flex flex-col items-center justify-center text-center opacity-50">
                        <svg className="w-8 h-8 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        <span className="text-sm font-medium text-zinc-400">No Citation Selected</span>
                        <span className="text-xs text-zinc-500 mt-1 max-w-[200px]">Click a citation pill in the chat to view the underlying database record.</span>
                      </div>
                    )}
                  </div>
                </div>
              </section>

              {/* ACTION 1: Interactive Security Investment Optimizer */}
              <section className="p-6 md:p-8 rounded-xl bg-zinc-900/50 border border-zinc-800 shadow-lg space-y-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-2xl font-medium text-white flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full bg-indigo-400"></span>
                      Security Investment Optimizer
                    </h2>
                    <p className="text-sm text-zinc-400 mt-1">
                      Mathematical optimization to maximize risk reduction per security dollar spent.
                    </p>
                  </div>

                  <div className="flex items-center gap-2 bg-zinc-800/50/80 p-1.5 rounded-xl border border-zinc-800">
                    <button
                      onClick={() => setStrategy('pulp')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                        strategy === 'pulp' ? 'bg-indigo-600 text-white text-zinc-950 shadow-md' : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      PuLP Exact Knapsack
                    </button>
                    <button
                      onClick={() => setStrategy('greedy')}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                        strategy === 'greedy' ? 'bg-indigo-600 text-white text-zinc-950 shadow-md' : 'text-zinc-400 hover:text-white'
                      }`}
                    >
                      Greedy ROI Sort
                    </button>
                  </div>
                </div>

                {/* Budget Slider & Input Controls */}
                <div className="bg-zinc-950/60 p-6 rounded-xl border border-zinc-800 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <label className="text-sm font-semibold text-zinc-300 uppercase tracking-wide">
                      Remediation Budget:
                    </label>
                    <div className="flex items-center gap-3">
                      <input
                        type="number"
                        min="1000"
                        max="250000"
                        step="1000"
                        value={budgetInput}
                        onChange={(e) => {
                          setBudgetInput(e.target.value);
                          const val = Number(e.target.value);
                          if (val > 0) setBudget(val);
                        }}
                        className="bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1 text-right text-indigo-400 font-mono font-medium text-lg w-36 focus:outline-none focus:border-indigo-500/50"
                      />
                      <span className="text-3xl font-semibold text-indigo-400 font-mono hidden sm:inline">
                        {formatCurrency(budget)}
                      </span>
                    </div>
                  </div>

                  <input
                    type="range"
                    min="5000"
                    max="250000"
                    step="5000"
                    value={budget}
                    onChange={(e) => {
                      const b = Number(e.target.value);
                      setBudget(b);
                      setBudgetInput(String(b));
                    }}
                    className="w-full h-3 bg-zinc-800/50 rounded-lg appearance-none cursor-pointer accent-indigo-400"
                  />

                  {/* Preset Quick Buttons */}
                  <div className="flex flex-wrap gap-2 pt-1">
                    <span className="text-xs text-zinc-400 self-center mr-1">Presets:</span>
                    {[
                      { val: 20000, label: '$20K' },
                      { val: 50000, label: '$50K' },
                      { val: 75000, label: '$75K' },
                      { val: 100000, label: '$100K' },
                      { val: 150000, label: '$150K' }
                    ].map((preset) => (
                      <button
                        key={preset.val}
                        onClick={() => {
                          setBudget(preset.val);
                          setBudgetInput(String(preset.val));
                        }}
                        className={`px-3 py-1 text-xs rounded-lg border transition-all ${
                          budget === preset.val
                            ? 'border-indigo-500/50 text-indigo-300 bg-indigo-950/40 font-semibold'
                            : 'border-zinc-800 text-zinc-400 hover:border-zinc-800 hover:text-zinc-300'
                        }`}
                      >
                        {preset.label}
                      </button>
                    ))}
                    {loadingOpt && (
                      <span className="text-xs text-indigo-400 animate-pulse self-center ml-2">
                        Optimizing integer program...
                      </span>
                    )}
                  </div>
                </div>

                {/* Optimization Outcome Cards */}
                {optResult && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 rounded-xl bg-zinc-800/50/40 border border-zinc-800/60">
                      <p className="text-xs text-zinc-400">Total Investment</p>
                      <p className="text-xl font-medium text-white font-mono mt-1">
                        {formatCurrency(optResult.total_cost_allocated)}
                      </p>
                      <p className="text-xs text-zinc-400 mt-1">{formatPercent(optResult.budget_utilization_pct, 1)} utilized</p>
                    </div>

                    <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30">
                      <p className="text-xs text-emerald-400 font-medium">Risk Reduction</p>
                      <p className="text-xl font-medium text-emerald-300 font-mono mt-1">
                        {formatCurrency(optResult.total_risk_reduction)}
                      </p>
                      <p className="text-xs text-emerald-400/80 mt-1">Loss eliminated</p>
                    </div>

                    <div className="p-4 rounded-xl bg-indigo-950/20 border border-zinc-800">
                      <p className="text-xs text-indigo-400 font-medium">Overall ROI</p>
                      <p className="text-xl font-medium text-indigo-300 font-mono mt-1">
                        {Number(optResult.overall_roi).toFixed(2)}x
                      </p>
                      <p className="text-xs text-indigo-400/80 mt-1">Risk$ / $ spent</p>
                    </div>

                    <div className="p-4 rounded-xl bg-zinc-800/50/40 border border-zinc-800/60">
                      <p className="text-xs text-zinc-400">Controls Selected</p>
                      <p className="text-xl font-medium text-zinc-200 font-mono mt-1">
                        {formatNumber(optResult.selected_actions.length)} fixes
                      </p>
                      <p className="text-xs text-zinc-400 mt-1">{optResult.strategy_used === 'pulp_knapsack_0_1' ? 'PuLP Mathematical Optimization' : 'Greedy ROI Optimization'}</p>
                    </div>
                  </div>
                )}

                {/* Pareto Frontier Optimization Curve */}
                {optResult && (
                  <div className="p-5 rounded-xl bg-zinc-950/80 border border-zinc-800 space-y-3">
                    <div className="flex flex-wrap justify-between items-center gap-2">
                      <div>
                        <h3 className="text-sm font-medium text-white flex items-center gap-2">
                          <span className="w-2.5 h-2.5 rounded-full bg-indigo-400"></span>
                          Pareto Frontier (Security Investment Efficiency Curve)
                        </h3>
                        <p className="text-xs text-zinc-400 mt-0.5">
                          Optimal trade-off frontier between budget allocated and quantified risk reduction (ΔALE). Demonstrates diminishing returns across budget levels.
                        </p>
                      </div>
                      {optResult.provenance && (
                        <div className="flex items-center gap-2">
                          <span className="text-[11px] font-mono text-indigo-300 bg-indigo-950/50 border border-zinc-800 px-2.5 py-1 rounded-lg">
                            🤖 {optResult.provenance.model_used}
                          </span>
                          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded">
                            Audit Trail Logged
                          </span>
                        </div>
                      )}
                    </div>
                    <div className="h-64 relative">
                      <canvas ref={paretoChartRef}></canvas>
                    </div>
                  </div>
                )}

                {/* AI-Augmented Candidate Controls Register & Ranking */}
                {optResult && (
                  <div className="space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <h3 className="text-base font-medium text-zinc-100 flex items-center gap-2">
                          <span>Ranked Candidate Controls Register</span>
                          <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-800/50 text-indigo-300">
                            Ranked by Marginal Utility (ΔALE / Cost)
                          </span>
                        </h3>
                        <p className="text-xs text-zinc-400 mt-0.5">
                          Every candidate control evaluated and ranked by cost-efficiency. Controls within the {formatCurrency(budget)} budget constraint are selected.
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs">
                        <button
                          type="button"
                          onClick={() => setControlFilter('all')}
                          className={`px-3 py-1 rounded font-medium transition-all ${controlFilter === 'all' ? 'bg-indigo-600 text-white font-medium' : 'text-zinc-400 hover:text-white'}`}>
                          All ({optResult.ranked_controls ? optResult.ranked_controls.length : optResult.selected_actions.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setControlFilter('selected')}
                          className={`px-3 py-1 rounded font-medium transition-all ${controlFilter === 'selected' ? 'bg-emerald-600 text-white font-medium' : 'text-zinc-400 hover:text-white'}`}>
                          Selected ({optResult.selected_actions.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setControlFilter('deferred')}
                          className={`px-3 py-1 rounded font-medium transition-all ${controlFilter === 'deferred' ? 'bg-rose-700 text-white font-medium' : 'text-zinc-400 hover:text-white'}`}>
                          Deferred ({optResult.ranked_controls ? optResult.ranked_controls.filter(c => !c.is_selected).length : 0})
                        </button>
                      </div>
                    </div>

                    {/* Manual Simulation Override Active Banner */}
                    {Object.keys(manualOverrides).length > 0 && (
                      <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 flex flex-wrap items-center justify-between gap-3 text-xs">
                        <div className="flex items-center gap-2">
                          <span className="text-base"></span>
                          <div>
                            <span className="font-medium text-amber-300">
                              Manual Simulation Override Active ({Object.keys(manualOverrides).length} override{Object.keys(manualOverrides).length > 1 ? 's' : ''}):
                            </span>
                            <span className="text-zinc-300 ml-1.5">
                              Allocated {formatCurrency(optResult.total_cost_allocated)} of {formatCurrency(budget)} budget ({optResult.budget_utilization_pct}%).
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {optResult.total_cost_allocated > budget && (
                            <span className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 font-medium border border-rose-500/40">
                               Over budget by {formatCurrency(optResult.total_cost_allocated - budget)}
                            </span>
                          )}
                          <button
                            type="button"
                            onClick={handleResetOverrides}
                            className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-white font-medium transition-all flex items-center gap-1"
                          >
                            <span>↺ Reset to PuLP Optimal</span>
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="overflow-x-auto border border-zinc-800 rounded-xl">
                      <table className="w-full text-left text-sm">
                        <thead className="bg-zinc-900/90 text-xs uppercase text-zinc-400 border-b border-zinc-800">
                          <tr>
                            <th className="px-3 py-3 text-center">Rank</th>
                            <th className="px-3 py-3">Status (Click to Toggle)</th>
                            <th className="px-3 py-3">Action ID</th>
                            <th className="px-4 py-3">Control Title</th>
                            <th className="px-3 py-3 text-right">Cost</th>
                            <th className="px-3 py-3 text-right">ΔALE Reduction</th>
                            <th className="px-3 py-3 text-center">ΔALE / Cost</th>
                            <th className="px-3 py-3 text-right">Cumul. Cost</th>
                            <th className="px-3 py-3 text-right">Cumul. ΔALE</th>
                            <th className="px-3 py-3 text-center">NIST CSF</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {(optResult.ranked_controls || optResult.selected_actions).filter(c => {
                            if (controlFilter === 'selected') return c.is_selected;
                            if (controlFilter === 'deferred') return !c.is_selected;
                            return true;
                          }).map((act, idx) => (
                            <tr key={act.action_id || idx} className={`hover:bg-zinc-800/50/30 transition-colors ${act.is_selected ? 'bg-emerald-950/10' : 'opacity-70'}`}>
                              <td className="px-3 py-3 text-center font-mono font-medium text-xs text-zinc-300">
                                #{act.rank || (idx + 1)}
                              </td>
                              <td className="px-3 py-3">
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleToggleControl(act.action_id);
                                  }}
                                  title="Click to toggle selection status (Manual Simulation Override)"
                                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all shadow-sm ${
                                    act.is_selected
                                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
                                      : 'bg-zinc-800/50 text-zinc-400 border border-zinc-800 hover:bg-rose-500/20 hover:text-rose-300'
                                  }`}
                                >
                                  <span>{act.is_selected ? '✓ SELECTED' : '✕ DEFERRED'}</span>
                                  <span className="text-[10px] opacity-70">🔄</span>
                                </button>
                              </td>
                              <td className="px-3 py-3 font-mono text-xs text-indigo-400 font-medium">{act.action_id}</td>
                              <td className="px-4 py-3">
                                <div className="font-medium text-zinc-200">{act.title}</div>
                                <div className="text-[11px] text-zinc-400 flex gap-2 mt-0.5">
                                  <span>Type: {act.remediation_type}</span>
                                  {act.finding_id && <span>• Finding: {act.finding_id}</span>}
                                </div>
                              </td>
                              <td className="px-3 py-3 text-right font-mono text-zinc-300">{formatCurrency(act.cost)}</td>
                              <td className="px-3 py-3 text-right font-mono text-emerald-400 font-semibold">{formatCurrency(act.risk_reduction_usd)}</td>
                              <td className="px-3 py-3 text-center font-mono font-medium text-indigo-300">
                                {Number(act.delta_ale_cost_ratio || act.roi || 0).toFixed(2)}x
                              </td>
                              <td className="px-3 py-3 text-right font-mono text-xs text-zinc-400">
                                {act.cumulative_cost ? formatCurrency(act.cumulative_cost) : '—'}
                              </td>
                              <td className="px-3 py-3 text-right font-mono text-xs text-emerald-500/90">
                                {act.cumulative_risk_reduction ? formatCurrency(act.cumulative_risk_reduction) : '—'}
                              </td>
                              <td className="px-3 py-3 text-center font-mono text-xs text-zinc-400">{act.nist_control_id || 'PR.IP-12'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </section>

              {/* Risk Charts Section */}
              <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md space-y-4">
                  <h3 className="text-lg font-medium text-zinc-100">Quantified Risk by Business Unit</h3>
                  <div className="h-64 relative">
                    <canvas ref={buChartRef}></canvas>
                  </div>
                </div>

                <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md space-y-4">
                  <h3 className="text-lg font-medium text-zinc-100">Risk by Asset Category</h3>
                  <div className="h-64 relative">
                    <canvas ref={catChartRef}></canvas>
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* Tab 2: Findings Explorer (Action 3: List Findings) */}
          {activeTab === 'findings' && (
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-2xl font-medium text-white">Security Findings Explorer</h2>
                  <p className="text-xs text-zinc-400 mt-1">Normalized security signals enriched with ML exploit probability and dollar risk.</p>
                </div>
                <button
                  onClick={fetchFindings}
                  disabled={loadingFindings}
                  className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-white font-medium text-xs flex items-center gap-2 self-start"
                >
                  {loadingFindings ? "Querying..." : "↻ Refresh Findings"}
                </button>
              </div>

              {/* Filters */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-zinc-950 p-4 rounded-xl border border-zinc-800">
                <div>
                  <label className="block text-xs font-semibold text-zinc-400 mb-1">Severity Filter</label>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-zinc-400 mb-1">Status Filter</label>
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                  >
                    <option value="all">All Statuses</option>
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="mitigated">Mitigated</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-zinc-400 mb-1">Search Findings / CVE</label>
                  <input
                    type="text"
                    placeholder="Search by CVE, runc, Log4j..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                  />
                </div>
              </div>

              {/* Findings Table */}
              <div className="overflow-x-auto border border-zinc-800 rounded-xl">
                <table className="w-full text-left text-sm">
                  <thead className="bg-zinc-950 text-xs uppercase text-zinc-400 border-b border-zinc-800">
                    <tr>
                      <th className="px-4 py-3">Finding ID</th>
                      <th className="px-4 py-3">CVE / Title</th>
                      <th className="px-4 py-3">Asset ID</th>
                      <th className="px-4 py-3 text-center">CVSS</th>
                      <th className="px-4 py-3 text-center">EPSS</th>
                      <th className="px-4 py-3 text-center">ML Exploit Prob</th>
                      <th className="px-4 py-3 text-center">Severity</th>
                      <th className="px-4 py-3 text-right">Quantified Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {findings.length === 0 ? (
                      <tr>
                        <td colSpan="8" className="text-center py-8 text-zinc-500">
                          No findings match the current filter criteria.
                        </td>
                      </tr>
                    ) : (
                      findings.map((f) => (
                        <tr
                          key={f.finding_id}
                          onClick={() => handleOpenDrilldown('finding', f.finding_id, f)}
                          className="hover:bg-indigo-950/30 cursor-pointer transition-colors group"
                          title="Click to open slide-over drill-down detail"
                        >
                          <td className="px-4 py-3 font-mono text-xs text-indigo-400 font-medium group-hover:text-indigo-300">
                            <span className="flex items-center gap-1">
                              {f.finding_id}
                              <span className="text-[10px] text-indigo-500 opacity-60 group-hover:opacity-100">↗</span>
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="font-semibold text-zinc-200 group-hover:text-white">{f.title}</div>
                            <div className="text-xs font-mono text-zinc-400">{f.cve_id || f.finding_type}</div>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-zinc-300">{f.asset_id}</td>
                          <td className="px-4 py-3 text-center font-mono font-semibold">{Number(f.cvss_score).toFixed(1)}</td>
                          <td className="px-4 py-3 text-center font-mono text-zinc-400">
                            {f.epss_score !== null && f.epss_score !== undefined ? `${(Number(f.epss_score) * 100).toFixed(1)}%` : '—'}
                          </td>
                          <td className="px-4 py-3 text-center font-mono text-amber-300 font-medium">
                            {formatPercent(Number(f.exploit_likelihood) * 100, 1)}
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium uppercase ${
                              f.severity === 'critical' ? 'bg-rose-500/20 text-rose-400 border border-zinc-800' :
                              f.severity === 'high' ? 'bg-orange-500/20 text-orange-500 border border-orange-500/20' :
                              f.severity === 'medium' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                              'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                            }`}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-right font-mono font-medium text-rose-400">
                            {formatCurrency(f.quantified_risk_usd)}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 3: Board Executive Report (Action 4) */}
          {activeTab === 'report' && execSummaryData && (
            <div className="p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
              <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
                <div>
                  <h2 className="text-2xl font-medium text-white">Board-Ready Executive Cyber Risk Report</h2>
                  <p className="text-xs text-zinc-400 mt-1">Generated dynamically from continuous quantified cyber risk and mathematical optimization.</p>
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(execSummaryData.executive_summary);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-white font-medium text-xs flex items-center gap-2"
                >
                  {copied ? "✓ Copied to Clipboard!" : "Copy Executive Summary"}
                </button>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800">
                  <p className="text-xs text-zinc-400">Total Risk Exposure</p>
                  <p className="text-2xl font-medium text-rose-400 mt-1">{execSummaryData.total_risk_exposure}</p>
                </div>
                <div className="p-4 bg-zinc-950 rounded-xl border border-blue-900/50">
                  <p className="text-[10px] text-indigo-400 uppercase tracking-wider font-medium">IBM Benchmark 2024</p>
                  <p className="text-2xl font-medium text-zinc-200 mt-1">{execSummaryData.ibm_benchmark_usd || '$4,880,000'}</p>
                </div>
                <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800">
                  <p className="text-xs text-zinc-400">Allocated Budget</p>
                  <p className="text-2xl font-medium text-indigo-400 mt-1">{execSummaryData.allocated_budget}</p>
                </div>
                <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800">
                  <p className="text-xs text-zinc-400">Projected Risk Reduction</p>
                  <p className="text-2xl font-medium text-emerald-400 mt-1">{execSummaryData.projected_risk_reduction}</p>
                </div>
                <div className="p-4 bg-zinc-950 rounded-xl border border-zinc-800">
                  <p className="text-xs text-zinc-400">Return on Investment</p>
                  <p className="text-2xl font-medium text-purple-400 mt-1">{execSummaryData.roi}</p>
                </div>
              </div>

              <div className="p-6 bg-zinc-950 rounded-xl border border-zinc-800">
                <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider mb-2">Executive Briefing Statement</h3>
                <p className="text-zinc-200 leading-relaxed text-base">
                  {execSummaryData.executive_summary}
                </p>
              </div>
            </div>
          )}

          {/* ===== Tab 5: Interactive FAIR Risk Calculator ===== */}
          {activeTab === 'risk-calc' && (
            <div className="p-6 md:p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
              <div>
                <h2 className="text-2xl font-medium text-white flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-amber-400"></span>
                  Interactive FAIR Risk Calculator
                </h2>
                <p className="text-sm text-zinc-400 mt-1">Model inherent & residual risk using Factor Analysis of Information Risk (FAIR) methodology.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Input Form */}
                <div className="space-y-4 bg-zinc-950 p-6 rounded-xl border border-zinc-800">
                  <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider mb-2">Risk Scenario Parameters</h3>

                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1 flex items-center justify-between">
                      <span>Live CVE ID (Optional)</span>
                      <span className="text-[9px] text-indigo-400 font-mono uppercase bg-indigo-950/50 px-1.5 py-0.5 rounded border border-zinc-800">Real-World Intel</span>
                    </label>
                    <input type="text" placeholder="e.g., CVE-2024-3094" value={riskCalcInputs.cve_id || ''}
                      onChange={e => setRiskCalcInputs({...riskCalcInputs, cve_id: e.target.value.toUpperCase()})}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-indigo-400 font-mono focus:outline-none focus:border-indigo-500/50 placeholder-slate-600 mb-4" />
                    
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Threat Event Frequency (events/year)</label>
                    <input type="number" min="0.1" max="365" step="0.5" value={riskCalcInputs.threat_event_frequency}
                      onChange={e => setRiskCalcInputs({...riskCalcInputs, threat_event_frequency: Number(e.target.value)})}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
                    <p className="text-xs text-zinc-500 mt-0.5">How often a threat agent contacts this asset per year</p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Vulnerability / Control Failure Probability</label>
                    <input type="range" min="0.01" max="1.0" step="0.01" value={riskCalcInputs.vulnerability_score}
                      onChange={e => setRiskCalcInputs({...riskCalcInputs, vulnerability_score: Number(e.target.value)})}
                      className="w-full h-2 bg-zinc-800/50 rounded-lg appearance-none cursor-pointer accent-amber-400" />
                    <div className="flex justify-between text-xs text-zinc-400 mt-1">
                      <span>Low (0.01)</span>
                      <span className="font-medium text-amber-300">{riskCalcInputs.vulnerability_score.toFixed(2)}</span>
                      <span>High (1.0)</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-zinc-400 mb-1">Primary Loss (USD)</label>
                      <input type="number" min="0" step="10000" value={riskCalcInputs.primary_loss_usd}
                        onChange={e => setRiskCalcInputs({...riskCalcInputs, primary_loss_usd: Number(e.target.value)})}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
                      <p className="text-xs text-zinc-500 mt-0.5">Direct recovery cost</p>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-zinc-400 mb-1">Secondary Loss (USD)</label>
                      <input type="number" min="0" step="10000" value={riskCalcInputs.secondary_loss_usd}
                        onChange={e => setRiskCalcInputs({...riskCalcInputs, secondary_loss_usd: Number(e.target.value)})}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
                      <p className="text-xs text-zinc-500 mt-0.5">Fines, legal, reputation</p>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Control Effectiveness (%)</label>
                    <input type="range" min="0" max="100" step="1" value={riskCalcInputs.control_effectiveness_pct}
                      onChange={e => setRiskCalcInputs({...riskCalcInputs, control_effectiveness_pct: Number(e.target.value)})}
                      className="w-full h-2 bg-zinc-800/50 rounded-lg appearance-none cursor-pointer accent-emerald-400" />
                    <div className="flex justify-between text-xs text-zinc-400 mt-1">
                      <span>None (0%)</span>
                      <span className="font-medium text-emerald-300">{riskCalcInputs.control_effectiveness_pct}%</span>
                      <span>Full (100%)</span>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Risk Appetite Threshold (USD)</label>
                    <input type="number" min="0" step="10000" value={riskCalcInputs.risk_appetite_threshold_usd}
                      onChange={e => setRiskCalcInputs({...riskCalcInputs, risk_appetite_threshold_usd: Number(e.target.value)})}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500/50" />
                  </div>

                  <button onClick={handleRiskCalc} disabled={loadingRiskCalc}
                    className="w-full px-6 py-3 bg-orange-600 text-white hover:bg-orange-500  disabled:bg-zinc-800 disabled:text-zinc-500 text-white font-medium rounded-lg transition-all flex items-center justify-center gap-2">
                    {loadingRiskCalc ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Calculating...</> : 'Calculate FAIR Risk'}
                  </button>
                </div>

                {/* Results Panel */}
                <div className="space-y-4">
                  {riskCalcResult ? (
                    <>
                      {/* Confidence-Banded Risk Range Outputs (Min / Likely / Max + P10 / P90) */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Inherent Risk Range Card */}
                        <div
                          onClick={() => handleOpenDrilldown('risk_calc', 'FAIR-CALC-INHERENT', riskCalcResult)}
                          className="p-4 rounded-xl bg-rose-950/30 border border-zinc-800 hover:border-rose-400/70 space-y-2.5 cursor-pointer transition-all group"
                          title="Click to inspect underlying scenario inputs, confidence band percentiles, and provenance"
                        >
                          <div className="flex justify-between items-center">
                            <span className="text-xs text-rose-300 font-semibold uppercase tracking-wide flex items-center gap-1.5">
                              <span>Inherent Loss (ALE Range)</span>
                              <span className="text-[10px] text-indigo-400 opacity-60 group-hover:opacity-100">🔍 Drill Down</span>
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-medium">5k Monte Carlo • 80% CI</span>
                          </div>
                          <div>
                            <div className="text-xl md:text-2xl font-medium text-rose-400 font-mono tracking-tight group-hover:text-rose-300">
                              {formatCurrency(riskCalcResult.inherent_ale_band?.min)} – {formatCurrency(riskCalcResult.inherent_ale_band?.max)}
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-xs text-zinc-400">Likely (P50):</span>
                              <span className="text-sm font-medium text-rose-200 font-mono">
                                {formatCurrency(riskCalcResult.inherent_ale_band?.p50 || riskCalcResult.inherent_risk_usd)}
                              </span>
                            </div>
                          </div>
                          <div className="p-2.5 bg-zinc-950/90 rounded-lg border border-zinc-800 text-xs space-y-1.5 font-mono">
                            <div className="flex justify-between text-zinc-300">
                              <span className="text-zinc-400">80% CI Band:</span>
                              <strong>{formatCurrency(riskCalcResult.inherent_ale_band?.p10)} – {formatCurrency(riskCalcResult.inherent_ale_band?.p90)}</strong>
                            </div>
                            <div className="w-full bg-zinc-800/50 h-1.5 rounded-full overflow-hidden flex">
                              <div style={{width: '20%'}} className="bg-rose-950"></div>
                              <div style={{width: '60%'}} className="bg-rose-500 rounded-full"></div>
                              <div style={{width: '20%'}} className="bg-rose-950"></div>
                            </div>
                            <div className="flex justify-between text-[11px] text-zinc-400">
                              <span>Min: {formatCurrency(riskCalcResult.inherent_ale_band?.min)}</span>
                              <span>Mean: {formatCurrency(riskCalcResult.inherent_ale_band?.mean || riskCalcResult.inherent_risk_usd)}</span>
                              <span>Max: {formatCurrency(riskCalcResult.inherent_ale_band?.max)}</span>
                            </div>
                          </div>
                        </div>

                        {/* Residual Risk Range Card */}
                        <div
                          onClick={() => handleOpenDrilldown('risk_calc', 'FAIR-CALC-RESIDUAL', riskCalcResult)}
                          className={`p-4 rounded-xl border space-y-2.5 cursor-pointer transition-all group ${
                            riskCalcResult.exceeds_appetite
                              ? 'bg-orange-950/30 border-orange-500/20 hover:border-orange-400/70'
                              : 'bg-emerald-950/30 border-emerald-500/30 hover:border-emerald-400/70'
                          }`}
                          title="Click to inspect underlying scenario inputs, confidence band percentiles, and provenance"
                        >
                          <div className="flex justify-between items-center">
                            <span className={`text-xs font-semibold uppercase tracking-wide flex items-center gap-1.5 ${riskCalcResult.exceeds_appetite ? 'text-orange-400' : 'text-emerald-300'}`}>
                              <span>Residual Loss (ALE Range)</span>
                              <span className="text-[10px] text-indigo-400 opacity-60 group-hover:opacity-100">🔍 Drill Down</span>
                            </span>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-medium ${riskCalcResult.exceeds_appetite ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'}`}>
                              {riskCalcResult.exceeds_appetite ? ' EXCEEDS APPETITE' : '✅ WITHIN APPETITE'}
                            </span>
                          </div>
                          <div>
                            <div className={`text-xl md:text-2xl font-medium font-mono tracking-tight ${riskCalcResult.exceeds_appetite ? 'text-orange-500 group-hover:text-orange-400' : 'text-emerald-400 group-hover:text-emerald-300'}`}>
                              {formatCurrency(riskCalcResult.residual_ale_band?.min)} – {formatCurrency(riskCalcResult.residual_ale_band?.max)}
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="text-xs text-zinc-400">Likely (P50):</span>
                              <span className={`text-sm font-medium font-mono ${riskCalcResult.exceeds_appetite ? 'text-orange-200' : 'text-emerald-200'}`}>
                                {formatCurrency(riskCalcResult.residual_ale_band?.p50 || riskCalcResult.residual_risk_usd)}
                              </span>
                            </div>
                          </div>
                          <div className="p-2.5 bg-zinc-950/90 rounded-lg border border-zinc-800 text-xs space-y-1.5 font-mono">
                            <div className="flex justify-between text-zinc-300">
                              <span className="text-zinc-400">80% CI Band:</span>
                              <strong className={riskCalcResult.exceeds_appetite ? 'text-orange-400' : 'text-emerald-300'}>
                                {formatCurrency(riskCalcResult.residual_ale_band?.p10)} – {formatCurrency(riskCalcResult.residual_ale_band?.p90)}
                              </strong>
                            </div>
                            <div className="w-full bg-zinc-800/50 h-1.5 rounded-full overflow-hidden flex">
                              <div style={{width: '20%'}} className={riskCalcResult.exceeds_appetite ? 'bg-orange-950' : 'bg-emerald-950'}></div>
                              <div style={{width: '60%'}} className={`${riskCalcResult.exceeds_appetite ? 'bg-orange-500' : 'bg-emerald-500'} rounded-full`}></div>
                              <div style={{width: '20%'}} className={riskCalcResult.exceeds_appetite ? 'bg-orange-950' : 'bg-emerald-950'}></div>
                            </div>
                            <div className="flex justify-between text-[11px] text-zinc-400">
                              <span>Min: {formatCurrency(riskCalcResult.residual_ale_band?.min)}</span>
                              <span>Mean: {formatCurrency(riskCalcResult.residual_ale_band?.mean || riskCalcResult.residual_risk_usd)}</span>
                              <span>Max: {formatCurrency(riskCalcResult.residual_ale_band?.max)}</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* LEF and Risk Reduction Confidence Bands */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div
                          onClick={() => handleOpenDrilldown('risk_calc', 'FAIR-CALC-LEF', riskCalcResult)}
                          className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 hover:border-indigo-500/60 space-y-2 cursor-pointer transition-all group"
                          title="Click to inspect underlying scenario inputs, confidence band percentiles, and provenance"
                        >
                          <div className="flex justify-between items-center text-xs text-zinc-400">
                            <span className="font-semibold uppercase tracking-wide flex items-center gap-1.5">
                              <span>Loss Event Frequency (LEF Range)</span>
                              <span className="text-[10px] text-indigo-400 opacity-60 group-hover:opacity-100">🔍 Drill Down</span>
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-indigo-300 font-medium">Beta-PERT Range</span>
                          </div>
                          <div>
                            <div className="text-lg md:text-xl font-medium font-mono text-indigo-400 group-hover:text-indigo-300">
                              {riskCalcResult.lef_band?.min?.toFixed(2) || '0.00'} – {riskCalcResult.lef_band?.max?.toFixed(2) || '0.00'}/yr
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-xs text-zinc-400">Likely (P50):</span>
                              <span className="text-xs font-medium text-indigo-200 font-mono">
                                {riskCalcResult.lef_band?.p50 !== undefined ? `${riskCalcResult.lef_band.p50.toFixed(2)}/yr` : `${riskCalcResult.fair_breakdown.loss_event_frequency}/yr`}
                              </span>
                            </div>
                          </div>
                          <div className="p-2 bg-zinc-900/80 rounded-lg border border-zinc-800 text-xs font-mono space-y-1">
                            <div className="flex justify-between text-zinc-400">
                              <span>80% CI:</span>
                              <strong className="text-indigo-300">{riskCalcResult.lef_band?.p10?.toFixed(2) || '0.00'} – {riskCalcResult.lef_band?.p90?.toFixed(2) || '0.00'}/yr</strong>
                            </div>
                            <div className="flex justify-between text-[11px] text-zinc-500">
                              <span>Min: {riskCalcResult.lef_band?.min?.toFixed(2) || '0.00'}/yr</span>
                              <span>Mean: {riskCalcResult.lef_band?.mean?.toFixed(2) || '0.00'}/yr</span>
                              <span>Max: {riskCalcResult.lef_band?.max?.toFixed(2) || '0.00'}/yr</span>
                            </div>
                          </div>
                        </div>

                        <div
                          onClick={() => handleOpenDrilldown('risk_calc', 'FAIR-CALC-REDUCTION', riskCalcResult)}
                          className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 hover:border-emerald-500/60 space-y-2 cursor-pointer transition-all group"
                          title="Click to inspect underlying scenario inputs, confidence band percentiles, and provenance"
                        >
                          <div className="flex justify-between items-center text-xs text-zinc-400">
                            <span className="font-semibold uppercase tracking-wide flex items-center gap-1.5">
                              <span>Risk Reduction (ΔALE Range)</span>
                              <span className="text-[10px] text-indigo-400 opacity-60 group-hover:opacity-100">🔍 Drill Down</span>
                            </span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-medium">Mitigated Risk</span>
                          </div>
                          <div>
                            <div className="text-lg md:text-xl font-medium font-mono text-emerald-400 group-hover:text-emerald-300">
                              {formatCurrency(riskCalcResult.reduction_band?.min || 0)} – {formatCurrency(riskCalcResult.reduction_band?.max || 0)}
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-xs text-zinc-400">Likely (P50):</span>
                              <span className="text-xs font-medium text-emerald-200 font-mono">
                                {formatCurrency(riskCalcResult.reduction_band?.p50 || riskCalcResult.risk_reduction_usd)}
                              </span>
                            </div>
                          </div>
                          <div className="p-2 bg-zinc-900/80 rounded-lg border border-zinc-800 text-xs font-mono space-y-1">
                            <div className="flex justify-between text-zinc-400">
                              <span>80% CI:</span>
                              <strong className="text-emerald-300">{formatCurrency(riskCalcResult.reduction_band?.p10 || 0)} – {formatCurrency(riskCalcResult.reduction_band?.p90 || 0)}</strong>
                            </div>
                            <div className="flex justify-between text-[11px] text-zinc-500">
                              <span>Min: {formatCurrency(riskCalcResult.reduction_band?.min || 0)}</span>
                              <span>Mean: {formatCurrency(riskCalcResult.reduction_band?.mean || 0)}</span>
                              <span>Max: {formatCurrency(riskCalcResult.reduction_band?.max || 0)}</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Confidence-Banded FAIR Visualization Chart */}
                      <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                        <div className="flex flex-wrap justify-between items-center gap-2">
                          <div className="flex items-center gap-2">
                            <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                              FAIR Confidence-Banded Risk Visualization
                            </h4>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-indigo-300">
                              {riskCalcChartMode === 'band' ? 'Band / Whisker Range Plot' : 'KDE Probability Density'}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="flex bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs">
                              <button
                                type="button"
                                onClick={() => setRiskCalcChartMode('band')}
                                className={`px-2.5 py-1 rounded-md font-medium transition-all ${riskCalcChartMode === 'band' ? 'bg-indigo-600 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'}`}>
                                Range Bands
                              </button>
                              <button
                                type="button"
                                onClick={() => setRiskCalcChartMode('pdf')}
                                className={`px-2.5 py-1 rounded-md font-medium transition-all ${riskCalcChartMode === 'pdf' ? 'bg-indigo-600 text-white shadow' : 'text-zinc-400 hover:text-zinc-200'}`}>
                                📈 Density Curves
                              </button>
                            </div>
                            <span className="text-[11px] font-mono text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded border border-amber-400/20">
                              Appetite: {formatCurrency(riskCalcInputs.risk_appetite_threshold_usd)}
                            </span>
                          </div>
                        </div>
                        <div className="h-60 relative">
                          <canvas ref={fairBandChartRef}></canvas>
                        </div>
                      </div>

                      <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800/20">
                        <h4 className="text-sm font-semibold text-indigo-400 mb-2">AI Recommendation</h4>
                        <p className="text-sm text-zinc-300 leading-relaxed">{riskCalcResult.action_recommendation}</p>
                      </div>

                      {riskCalcResult.fair_breakdown && (
                        <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                          <h4 className="text-sm font-semibold text-zinc-300 mb-3">FAIR Methodology Breakdown & Ranges</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                            {Object.entries(riskCalcResult.fair_breakdown).map(([key, val]) => (
                              <div key={key} className="flex justify-between py-1 border-b border-zinc-800/50">
                                <span className="text-zinc-400">{key.replace(/_/g, ' ')}</span>
                                <span className="font-mono text-zinc-200 font-semibold">{typeof val === 'number' ? (key.includes('usd') ? formatCurrency(val) : val.toLocaleString()) : String(val)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="flex items-center justify-center h-full text-zinc-500 text-sm bg-zinc-950 rounded-xl border border-zinc-800 p-12">
                      Configure risk parameters and click "Calculate FAIR Risk" to see results.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ===== Tab 6: Compliance Gap Analysis ===== */}
          {activeTab === 'compliance' && (
            <ComplianceGapModule 
              complianceData={complianceData}
              loadingCompliance={loadingCompliance}
              fetchComplianceGap={fetchComplianceGap}
              formatCurrency={formatCurrency}
            />
          )}

          {/* ===== Tab 7: GRC Audit Trail ===== */}
          {activeTab === 'audit' && (
            <div className="space-y-6">
              {/* Log New Decision Form */}
              <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md space-y-4">
                <h2 className="text-2xl font-medium text-white flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-emerald-400"></span>
                  Log GRC Decision
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Action Type</label>
                    <select value={auditForm.action_type}
                      onChange={e => setAuditForm({...auditForm, action_type: e.target.value})}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50">
                      <option value="RISK_ACCEPTED">Risk Accepted</option>
                      <option value="BUDGET_ALLOCATED">Budget Allocated</option>
                      <option value="CONTROL_EXCEPTION">Control Exception</option>
                      <option value="POLICY_APPROVED">Policy Approved</option>
                      <option value="FINDING_ESCALATED">Finding Escalated</option>
                      <option value="VENDOR_RISK_REVIEWED">Vendor Risk Reviewed</option>
                      <option value="RISK_ASSESSMENT">Risk Assessment</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Actor</label>
                    <input type="text" value={auditForm.actor}
                      onChange={e => setAuditForm({...auditForm, actor: e.target.value})}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                      placeholder="Jane Smith, CISO" />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Framework Reference</label>
                    <input type="text" value={auditForm.framework_ref}
                      onChange={e => setAuditForm({...auditForm, framework_ref: e.target.value})}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50"
                      placeholder="NIST CSF 2.0 ID.RA-6" />
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="md:col-span-3">
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Decision Details / Justification</label>
                    <textarea value={auditForm.details} rows={2}
                      onChange={e => setAuditForm({...auditForm, details: e.target.value})}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50 resize-none"
                      placeholder="Accepted residual risk for legacy payment gateway pending Q3 migration project..." />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-zinc-400 mb-1">Financial Impact (USD)</label>
                    <input type="number" min="0" step="1000" value={auditForm.impact_usd}
                      onChange={e => setAuditForm({...auditForm, impact_usd: Number(e.target.value)})}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500/50" />
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={createAuditEntry} disabled={loadingAudit}
                    className="px-6 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-zinc-800 text-white font-medium text-xs rounded-lg transition-all flex items-center gap-2">
                    {loadingAudit ? 'Saving...' : 'Record Decision'}
                  </button>
                  <button onClick={() => {
                      const csv = 'Timestamp,Action,Actor,Details,Framework,Impact USD\n' +
                        auditLogs.map(l => `"${l.timestamp}","${l.action_type}","${l.actor}","${l.details.replace(/"/g,'""')}","${l.framework_ref}",${l.impact_usd}`).join('\n');
                      navigator.clipboard.writeText(csv);
                      showToast('Audit trail copied as CSV', 'success');
                    }}
                    className="px-4 py-2 bg-zinc-800/50 hover:bg-zinc-800 text-zinc-300 text-xs rounded-lg border border-zinc-800">
                    Copy as CSV
                  </button>
                </div>
              </div>

              {/* Audit Log Table */}
              <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 shadow-md space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-medium text-white">Decision Audit Trail ({auditLogs.length} entries)</h3>
                  <div className="flex gap-2 items-center">
                    <select value={auditFilterType} onChange={e => { setAuditFilterType(e.target.value); }}
                      className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-indigo-500/50">
                      <option value="all">All Types</option>
                      <option value="RISK_ACCEPTED">Risk Accepted</option>
                      <option value="BUDGET_ALLOCATED">Budget Allocated</option>
                      <option value="CONTROL_EXCEPTION">Control Exception</option>
                      <option value="POLICY_APPROVED">Policy Approved</option>
                      <option value="FINDING_ESCALATED">Finding Escalated</option>
                    </select>
                    <button onClick={fetchAuditLogs} className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-white font-medium text-xs rounded-lg">↻ Refresh</button>
                  </div>
                </div>
                <div className="overflow-x-auto border border-zinc-800 rounded-xl">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-zinc-950 text-xs uppercase text-zinc-400 border-b border-zinc-800">
                      <tr>
                        <th className="px-4 py-3">Timestamp</th>
                        <th className="px-4 py-3">Action</th>
                        <th className="px-4 py-3">Actor</th>
                        <th className="px-4 py-3">Details</th>
                        <th className="px-4 py-3">Framework</th>
                        <th className="px-4 py-3 text-right">Impact</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {auditLogs.length === 0 ? (
                        <tr><td colSpan="6" className="text-center py-8 text-zinc-500">No audit entries. Use the form above to record GRC decisions.</td></tr>
                      ) : auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-zinc-800/50/30 transition-colors">
                          <td className="px-4 py-3 text-xs font-mono text-zinc-400">{new Date(log.timestamp).toLocaleString()}</td>
                          <td className="px-4 py-3"><span className="px-2 py-0.5 rounded text-xs font-medium bg-indigo-500/10 text-indigo-400 text-indigo-300">{log.action_type}</span></td>
                          <td className="px-4 py-3 text-sm text-zinc-200">{log.actor}</td>
                          <td className="px-4 py-3 text-xs text-zinc-300 max-w-xs truncate" title={log.details}>{log.details}</td>
                          <td className="px-4 py-3 text-xs font-mono text-purple-300">{log.framework_ref}</td>
                          <td className="px-4 py-3 text-right font-mono text-sm text-amber-300">{formatCurrency(log.impact_usd)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ===== Tab 8: Policy-to-Control Mapper ===== */}
          {activeTab === 'policy' && (
            <div className="p-6 md:p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
              <div>
                <h2 className="text-2xl font-medium text-white flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-blue-400"></span>
                  Policy-to-Control Mapper
                </h2>
                <p className="text-sm text-zinc-400 mt-1">Paste organizational policy text to automatically map to NIST CSF 2.0 & ISO 27001 controls.</p>
              </div>

              <div className="bg-zinc-950 p-6 rounded-xl border border-zinc-800 space-y-4">
                <label className="block text-sm font-semibold text-zinc-300">Organizational Policy Text</label>
                <textarea value={policyText} rows={5}
                  onChange={e => setPolicyText(e.target.value)}
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-indigo-500/50 resize-none"
                  placeholder="Example: All internet-facing systems must undergo quarterly vulnerability scanning and critical findings must be remediated within 30 days. Multi-factor authentication is required for all privileged access to production systems. Data at rest must be encrypted using AES-256..." />
                <div className="flex gap-3">
                  <button onClick={handlePolicyMapping} disabled={loadingPolicy}
                    className="px-6 py-2.5 bg-indigo-600 text-white hover:bg-indigo-500  disabled:bg-zinc-800 disabled:text-zinc-500 text-white font-medium text-sm rounded-lg transition-all flex items-center gap-2">
                    {loadingPolicy ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Mapping...</> : 'Map Controls'}
                  </button>
                  <button onClick={() => setPolicyText('All internet-facing systems must undergo quarterly vulnerability scanning and critical findings must be remediated within 30 days. Multi-factor authentication is required for all privileged access to production systems. Security awareness training must be completed annually by all employees. Encryption at rest and in transit is mandatory for all sensitive data. Incident response plans must be tested semi-annually.')}
                    className="px-4 py-2.5 bg-zinc-800/50 hover:bg-zinc-800 text-zinc-300 text-xs rounded-lg border border-zinc-800">
                    Load Sample Policy
                  </button>
                </div>
              </div>

              {policyResult && (
                <div className="space-y-6">
                  {/* Summary Bar */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <p className="text-xs text-indigo-400 font-semibold">Coverage Score</p>
                      <p className={`text-3xl font-medium mt-1 ${policyResult.overall_coverage_score >= 80 ? 'text-emerald-400' : policyResult.overall_coverage_score >= 60 ? 'text-amber-400' : 'text-rose-400'}`}>
                        {policyResult.overall_coverage_score}%
                      </p>
                    </div>
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <p className="text-xs text-zinc-400">NIST Controls</p>
                      <p className="text-3xl font-medium text-indigo-300 mt-1">{policyResult.total_nist_controls_matched}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <p className="text-xs text-zinc-400">ISO Controls</p>
                      <p className="text-3xl font-medium text-purple-300 mt-1">{policyResult.total_iso_controls_matched}</p>
                    </div>
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <p className="text-xs text-zinc-400">Gaps</p>
                      <p className="text-3xl font-medium text-rose-400 mt-1">{policyResult.unmapped_areas.length}</p>
                    </div>
                  </div>

                  {/* Policy Summary */}
                  <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800/20">
                    <p className="text-sm text-zinc-300 leading-relaxed">{policyResult.policy_summary}</p>
                  </div>

                  {/* Unmapped Areas */}
                  {policyResult.unmapped_areas.length > 0 && (
                    <div className="p-4 rounded-xl bg-rose-950/20 border border-zinc-800">
                      <h4 className="text-sm font-medium text-rose-300 mb-2"> Unmapped Framework Areas</h4>
                      <div className="flex gap-2 flex-wrap">
                        {policyResult.unmapped_areas.map(area => (
                          <span key={area} className="px-3 py-1 bg-rose-500/20 text-rose-300 rounded-full text-xs font-medium">{area}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* NIST Mappings */}
                  <div>
                    <h3 className="text-lg font-medium text-indigo-300 mb-3">NIST CSF 2.0 Control Mappings</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {policyResult.nist_csf_mappings.map((m, idx) => (
                        <div key={idx} className="flex items-center gap-3 bg-zinc-950 p-3 rounded-lg border border-zinc-800">
                          <span className="font-mono text-xs text-indigo-400 font-medium w-16">{m.control_id}</span>
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${m.function === 'IDENTIFY' ? 'bg-blue-500/20 text-indigo-300' : m.function === 'PROTECT' ? 'bg-emerald-500/20 text-emerald-300' : m.function === 'DETECT' ? 'bg-amber-500/20 text-amber-300' : m.function === 'RESPOND' ? 'bg-orange-500/20 text-orange-400' : 'bg-purple-500/20 text-purple-300'}`}>{m.function}</span>
                          <span className="text-xs text-zinc-300 flex-1">{m.description}</span>
                          <div className="w-16 text-right">
                            <div className="h-1.5 bg-zinc-800/50 rounded-full overflow-hidden">
                              <div className="h-full bg-indigo-600 text-white rounded-full" style={{width: `${m.relevance_score}%`}}></div>
                            </div>
                            <span className="text-xs text-indigo-400">{m.relevance_score}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* ISO Mappings */}
                  <div>
                    <h3 className="text-lg font-medium text-purple-300 mb-3">ISO 27001:2022 Annex A Mappings</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {policyResult.iso_27001_mappings.map((m, idx) => (
                        <div key={idx} className="flex items-center gap-3 bg-zinc-950 p-3 rounded-lg border border-zinc-800">
                          <span className="font-mono text-xs text-purple-400 font-medium w-12">{m.control_id}</span>
                          <span className="text-xs text-zinc-300 flex-1">{m.description}</span>
                          <div className="w-16 text-right">
                            <div className="h-1.5 bg-zinc-800/50 rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{width: `${m.relevance_score}%`}}></div>
                            </div>
                            <span className="text-xs text-purple-400">{m.relevance_score}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ===== Tab 9: What-If Scenario Analysis ===== */}
          {activeTab === 'scenarios' && (
            <div className="p-6 md:p-8 rounded-xl bg-zinc-900 border border-zinc-800 shadow-lg space-y-6">
              <div>
                <h2 className="text-2xl font-medium text-white flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-indigo-400"></span>
                  What-If Budget Scenario Comparator
                </h2>
                <p className="text-sm text-zinc-400 mt-1">Compare multiple security budget allocations side-by-side using PuLP optimization.</p>
              </div>

              {/* Scenario Builder */}
              <div className="bg-zinc-950 p-6 rounded-xl border border-zinc-800 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-indigo-400 uppercase tracking-wider">Budget Scenarios</h3>
                  <button onClick={addScenario} disabled={scenarios.length >= 10}
                    className="px-3 py-1.5 bg-zinc-800/50 hover:bg-zinc-800 text-zinc-300 text-xs rounded-lg border border-zinc-800 disabled:opacity-40">
                    + Add Scenario
                  </button>
                </div>
                <div className="space-y-2">
                  {scenarios.map((s, idx) => (
                    <div key={idx} className="flex items-center gap-3 bg-zinc-900 p-3 rounded-lg border border-zinc-800">
                      <span className="w-6 h-6 flex items-center justify-center rounded-full bg-indigo-500/30 text-indigo-300 font-medium text-xs">{idx + 1}</span>
                      <input type="text" value={s.name} onChange={e => updateScenario(idx, 'name', e.target.value)}
                        className="flex-1 bg-zinc-950 border border-zinc-800 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500/50"
                        placeholder="Scenario name" />
                      <div className="flex items-center gap-1">
                        <span className="text-xs text-zinc-400">$</span>
                        <input type="number" min="1000" step="5000" value={s.budget} onChange={e => updateScenario(idx, 'budget', e.target.value)}
                          className="w-28 bg-zinc-950 border border-zinc-800 rounded px-3 py-1.5 text-sm text-indigo-300 font-mono focus:outline-none focus:border-indigo-500/50" />
                      </div>
                      <button onClick={() => removeScenario(idx)} disabled={scenarios.length <= 1}
                        className="text-rose-400 hover:text-rose-300 disabled:text-slate-600 text-sm px-2">✕</button>
                    </div>
                  ))}
                </div>
                <button onClick={handleScenarioAnalysis} disabled={loadingScenarios}
                  className="w-full px-6 py-3 bg-indigo-600 text-white hover:bg-indigo-500  disabled:bg-zinc-800 disabled:text-zinc-500 text-white font-medium rounded-lg transition-all flex items-center justify-center gap-2">
                  {loadingScenarios ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div> Optimizing...</> : 'Compare Scenarios'}
                </button>
              </div>

              {/* Scenario Results */}
              {scenarioResult && (
                <div className="space-y-6">
                  {/* Comparison Table */}
                  <div className="overflow-x-auto border border-zinc-800 rounded-xl">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-zinc-950 text-xs uppercase text-zinc-400 border-b border-zinc-800">
                        <tr>
                          <th className="px-4 py-3">Scenario</th>
                          <th className="px-4 py-3 text-right">Budget</th>
                          <th className="px-4 py-3 text-right">Allocated</th>
                          <th className="px-4 py-3 text-right">Utilization</th>
                          <th className="px-4 py-3 text-right">Residual ALE Range (Min — Likely — Max)</th>
                          <th className="px-4 py-3 text-right">Residual LEF Range</th>
                          <th className="px-4 py-3 text-right">Risk Reduction (ΔALE Range)</th>
                          <th className="px-4 py-3 text-center">ROI</th>
                          <th className="px-4 py-3 text-center">Controls</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {scenarioResult.scenarios.map((s, idx) => (
                          <tr key={idx} className={`hover:bg-zinc-800/50/30 transition-colors ${s.name === scenarioResult.best_roi_scenario ? 'bg-emerald-950/10' : ''}`}>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-zinc-200">{s.name}</span>
                                {s.name === scenarioResult.best_roi_scenario && <span className="px-1.5 py-0.5 bg-emerald-500/20 text-emerald-300 text-xs rounded font-medium">Best ROI</span>}
                                {s.name === scenarioResult.best_efficiency_scenario && s.name !== scenarioResult.best_roi_scenario && <span className="px-1.5 py-0.5 bg-indigo-500/10 text-indigo-400 text-indigo-300 text-xs rounded font-medium">Most Efficient</span>}
                              </div>
                            </td>
                            <td className="px-4 py-3 text-right font-mono text-zinc-300">{s.error ? '—' : formatCurrency(s.budget)}</td>
                            <td className="px-4 py-3 text-right font-mono text-indigo-300">{s.error ? '—' : formatCurrency(s.total_cost_allocated)}</td>
                            <td className="px-4 py-3 text-right font-mono text-zinc-300">{s.error ? '—' : formatPercent(s.budget_utilization_pct, 1)}</td>
                            <td className="px-4 py-3 text-right font-mono text-xs">
                              {s.error ? '—' : (
                                <div>
                                  <div className="text-indigo-300 font-medium">
                                    {formatCurrency(s.confidence_band?.min)} – {formatCurrency(s.confidence_band?.max)}
                                  </div>
                                  <div className="text-[11px] text-zinc-300">
                                    Likely (P50): <strong className="text-white">{formatCurrency(s.confidence_band?.p50)}</strong>
                                  </div>
                                  <div className="text-[10px] text-zinc-400">
                                    80% CI: {formatCurrency(s.confidence_band?.p10)} – {formatCurrency(s.confidence_band?.p90)}
                                  </div>
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 text-right font-mono text-xs">
                              {s.error ? '—' : (
                                <div>
                                  <div className="text-indigo-400 font-medium">
                                    {s.confidence_band?.lef_band?.p50 !== undefined ? `${s.confidence_band.lef_band.p50.toFixed(2)}/yr` : '—'}
                                  </div>
                                  <div className="text-[10px] text-zinc-400">
                                    {s.confidence_band?.lef_band ? `${s.confidence_band.lef_band.min.toFixed(2)} – ${s.confidence_band.lef_band.max.toFixed(2)}/yr` : '—'}
                                  </div>
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 text-right font-mono text-xs">
                              {s.error ? '—' : (
                                <div>
                                  <div className="font-medium text-emerald-400">
                                    {formatCurrency(s.total_risk_reduction)}
                                  </div>
                                  {s.confidence_band?.reduction_band && (
                                    <div className="text-[10px] text-emerald-500/80">
                                      Range: {formatCurrency(s.confidence_band.reduction_band.min)} – {formatCurrency(s.confidence_band.reduction_band.max)}
                                    </div>
                                  )}
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 text-center font-mono font-medium text-amber-300">{s.error ? '—' : `${Number(s.overall_roi).toFixed(2)}x`}</td>
                            <td className="px-4 py-3 text-center font-mono font-medium text-zinc-200">{s.error ? '—' : formatNumber(s.controls_selected)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Scenario Confidence Band Comparison Chart */}
                  <div className="p-5 rounded-xl bg-zinc-950 border border-zinc-800 space-y-3">
                    <div className="flex flex-wrap justify-between items-center gap-2">
                      <div>
                        <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                          Scenario Residual Risk Confidence Bands (Full Min-Max & 80% CI Band)
                        </h4>
                        <p className="text-[11px] text-zinc-500 mt-0.5">
                          Band chart: Outer translucent bar shows Min–Max range; inner solid band shows 80% CI (P10–P90); white point marker shows Likely (P50).
                        </p>
                      </div>
                      <span className="text-xs text-indigo-400 font-mono bg-indigo-950/40 border border-zinc-800 px-2.5 py-1 rounded">
                        PuLP Optimal Range
                      </span>
                    </div>
                    <div className="h-64 relative">
                      <canvas ref={scenarioBandChartRef}></canvas>
                    </div>
                  </div>

                  {/* Recommendation */}
                  <div className="p-5 rounded-xl bg-zinc-950 border border-indigo-500/30">
                    <h4 className="text-sm font-semibold text-indigo-400 mb-2">Analysis & Recommendation</h4>
                    <p className="text-sm text-zinc-300 leading-relaxed">{scenarioResult.recommendation}</p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ======================================================== */}
          {/* PHASE 4: GENERIC REUSABLE SLIDE-OVER DRILL-DOWN PANEL    */}
          {/* ======================================================== */}
          {slideoverOpen && (
            <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
              {/* Backdrop overlay */}
              <div
                className="fixed inset-0 bg-zinc-950/75 backdrop-blur-sm transition-opacity"
                onClick={handleCloseDrilldown}
              ></div>

              {/* Slide-over panel container */}
              <div className="relative w-full max-w-2xl bg-zinc-900 border-l border-zinc-800 shadow-lg z-10 flex flex-col h-full overflow-y-auto transform transition-transform duration-300">
                {/* Header */}
                <div className="p-6 bg-zinc-950/95 border-b border-zinc-800 flex items-center justify-between sticky top-0 z-20">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-indigo-500/10 text-indigo-400 border border-zinc-800 flex items-center justify-center text-indigo-300 font-medium text-lg">
                      {slideoverType === 'finding' ? <Search className="w-5 h-5" /> : <Scale className="w-5 h-5" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-medium text-white">
                          {slideoverType === 'finding' ? 'Security Finding Drill-Down' : 'FAIR Calculation Provenance'}
                        </h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-zinc-800 uppercase">
                          Read-Only
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 font-mono mt-0.5">
                        Target ID: <span className="text-indigo-400 font-medium">{slideoverId}</span>
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={handleCloseDrilldown}
                    className="w-8 h-8 rounded-lg bg-zinc-800/50 hover:bg-zinc-800 text-zinc-300 hover:text-white flex items-center justify-center transition-colors text-base"
                    title="Close drilldown (Esc)"
                  >
                    ✕
                  </button>
                </div>

                {/* Content Body */}
                <div className="p-6 space-y-6 flex-1">
                  {slideoverLoading ? (
                    <div className="py-20 flex flex-col items-center justify-center gap-3 text-indigo-400">
                      <div className="w-8 h-8 border-2 border-indigo-500/50 border-t-transparent rounded-full animate-spin"></div>
                      <span className="text-sm font-medium">Loading record details, controls, and audit trail...</span>
                    </div>
                  ) : slideoverDetail ? (
                    <>
                      {/* Sensitive Badge if applicable */}
                      {(slideoverDetail.finding_detail?.is_sensitive || slideoverDetail.risk_calc_detail?.is_sensitive || slideoverDetail.audit_logged) && (
                        <div className="p-3.5 bg-rose-950/40 border border-rose-500/40 rounded-xl flex items-center justify-between text-xs text-rose-300">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping"></span>
                            <strong>Restricted / Sensitive Record</strong>
                          </div>
                          <span className="font-mono text-[10px] bg-rose-900/60 px-2 py-0.5 rounded border border-zinc-800">
                            Audit Log Recorded #{slideoverDetail.audit_log_id || 'LOGGED'}
                          </span>
                        </div>
                      )}

                      {/* 1. FINDING DRILL-DOWN VIEW */}
                      {slideoverType === 'finding' && slideoverDetail.finding_detail && (
                        <div className="space-y-6">
                          {/* Finding Overview */}
                          <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-3">
                            <div className="flex justify-between items-start gap-3">
                              <div>
                                <span className="text-xs font-mono text-indigo-400 uppercase tracking-wide">
                                  {slideoverDetail.finding_detail.finding.finding_id}
                                </span>
                                <h4 className="text-base font-medium text-white mt-1">
                                  {slideoverDetail.finding_detail.finding.title}
                                </h4>
                                <p className="text-xs text-zinc-400 mt-1 font-mono">
                                  CVE: {slideoverDetail.finding_detail.finding.cve_id || 'N/A'} • Status: <span className="text-indigo-300 capitalize">{slideoverDetail.finding_detail.finding.status}</span>
                                </p>
                              </div>
                              <span className={`px-3 py-1 rounded-full text-xs font-medium uppercase ${
                                slideoverDetail.finding_detail.finding.severity === 'critical' ? 'bg-rose-500/20 text-rose-300 border border-zinc-800' :
                                slideoverDetail.finding_detail.finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/20' :
                                'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              }`}>
                                {slideoverDetail.finding_detail.finding.severity}
                              </span>
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-zinc-800 text-center font-mono">
                              <div className="p-2.5 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-[10px] text-zinc-400 block uppercase">CVSS Score</span>
                                <span className="text-base font-medium text-white">{Number(slideoverDetail.finding_detail.finding.cvss_score).toFixed(1)}</span>
                              </div>
                              <div className="p-2.5 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-[10px] text-zinc-400 block uppercase">EPSS Prob</span>
                                <span className="text-base font-medium text-zinc-300">
                                  {slideoverDetail.finding_detail.finding.epss_score !== null && slideoverDetail.finding_detail.finding.epss_score !== undefined ? `${(Number(slideoverDetail.finding_detail.finding.epss_score) * 100).toFixed(1)}%` : '—'}
                                </span>
                              </div>
                              <div className="p-2.5 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-[10px] text-zinc-400 block uppercase">ML Exploit Prob</span>
                                <span className="text-base font-medium text-amber-300">
                                  {formatPercent(Number(slideoverDetail.finding_detail.finding.exploit_likelihood) * 100, 1)}
                                </span>
                              </div>
                              <div className="p-2.5 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-[10px] text-zinc-400 block uppercase">Quantified Risk</span>
                                <span className="text-base font-medium text-rose-400">{formatCurrency(slideoverDetail.finding_detail.finding.quantified_risk_usd)}</span>
                              </div>
                            </div>
                          </div>

                          {/* Associated Asset Context */}
                          {slideoverDetail.finding_detail.asset && (
                            <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-3">
                              <h5 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-2">
                                <span>🖥️</span> Impacted Asset Context
                              </h5>
                              <div className="grid grid-cols-2 gap-4 text-xs">
                                <div>
                                  <span className="text-zinc-400">Asset Name:</span>
                                  <p className="font-semibold text-white mt-0.5">{slideoverDetail.finding_detail.asset.asset_name}</p>
                                </div>
                                <div>
                                  <span className="text-zinc-400">Asset ID:</span>
                                  <p className="font-mono text-indigo-300 mt-0.5">{slideoverDetail.finding_detail.asset.asset_id}</p>
                                </div>
                                <div>
                                  <span className="text-zinc-400">Business Unit:</span>
                                  <p className="text-zinc-200 mt-0.5">{slideoverDetail.finding_detail.asset.business_unit}</p>
                                </div>
                                <div>
                                  <span className="text-zinc-400">Asset Category:</span>
                                  <p className="text-zinc-200 mt-0.5 capitalize">{slideoverDetail.finding_detail.asset.asset_category}</p>
                                </div>
                                <div>
                                  <span className="text-zinc-400">Asset Value:</span>
                                  <p className="font-mono text-emerald-400 font-medium mt-0.5">{formatCurrency(slideoverDetail.finding_detail.asset.asset_value)}</p>
                                </div>
                                <div>
                                  <span className="text-zinc-400">Criticality:</span>
                                  <p className="capitalize font-semibold text-amber-300 mt-0.5">{slideoverDetail.finding_detail.asset.criticality}</p>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Related Candidate Controls */}
                          <div className="space-y-3">
                            <h5 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-2">
                              <span>🛡️</span> Available Candidate Remediation Controls ({slideoverDetail.finding_detail.remediations.length})
                            </h5>
                            {slideoverDetail.finding_detail.remediations.length === 0 ? (
                              <p className="text-xs text-zinc-500 italic p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                                No candidate remediations mapped for this finding.
                              </p>
                            ) : (
                              <div className="space-y-2">
                                {slideoverDetail.finding_detail.remediations.map((r, rIdx) => (
                                  <div key={rIdx} className="p-4 bg-zinc-950 rounded-xl border border-zinc-800 space-y-2">
                                    <div className="flex justify-between items-start gap-2">
                                      <div>
                                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                                          {r.action_id}
                                        </span>
                                        <p className="text-sm font-semibold text-zinc-200 mt-1">{r.title}</p>
                                      </div>
                                      <span className="text-xs font-mono text-indigo-300 font-medium">
                                        {Number(r.roi).toFixed(2)}x ROI
                                      </span>
                                    </div>
                                    <div className="flex flex-wrap gap-4 text-xs font-mono text-zinc-400 pt-2 border-t border-zinc-800">
                                      <span>Cost: <strong className="text-white">{formatCurrency(r.cost)}</strong></span>
                                      <span>ΔALE Reduction: <strong className="text-emerald-400">{formatCurrency(r.risk_reduction_usd)}</strong></span>
                                      <span>Effort: <strong className="text-zinc-300">{r.effort_hours}h</strong></span>
                                      {r.nist_control_id && <span>NIST: <strong className="text-indigo-300">{r.nist_control_id}</strong></span>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* MITRE Technique Mapping */}
                          {slideoverDetail.finding_detail.mitre_mapping && (
                            <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-2">
                              <h5 className="text-xs font-semibold text-purple-400 uppercase tracking-wider flex items-center gap-2">
                                <span>🎯</span> MITRE ATT&CK Technique Alignment
                              </h5>
                              <div className="flex items-center justify-between text-xs">
                                <span className="font-mono text-purple-300 font-medium bg-purple-950/60 px-2.5 py-1 rounded border border-purple-500/30">
                                  {slideoverDetail.finding_detail.mitre_mapping.technique_id}
                                </span>
                                <span className="text-zinc-400">
                                  {slideoverDetail.finding_detail.mitre_mapping.tactic}
                                </span>
                              </div>
                              <p className="text-xs text-zinc-300 mt-1">
                                Framework reference: <span className="font-mono text-indigo-300">{slideoverDetail.finding_detail.mitre_mapping.framework_ref}</span>
                              </p>
                            </div>
                          )}

                          {/* Linked Audit Trail Entries */}
                          <div className="space-y-3">
                            <h5 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider flex items-center gap-2">
                              <span>📜</span> Linked Audit Trail History ({slideoverDetail.finding_detail.linked_audit_logs.length})
                            </h5>
                            {slideoverDetail.finding_detail.linked_audit_logs.length === 0 ? (
                              <p className="text-xs text-zinc-500 italic p-3 bg-zinc-950 rounded-xl border border-zinc-800">
                                No previous audit trail records directly reference this finding ID.
                              </p>
                            ) : (
                              <div className="space-y-2">
                                {slideoverDetail.finding_detail.linked_audit_logs.map((a, aIdx) => (
                                  <div key={aIdx} className="p-3.5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-1 text-xs">
                                    <div className="flex justify-between items-center text-zinc-400">
                                      <span className="font-mono text-indigo-300 font-medium">#{a.id} • {a.action_type}</span>
                                      <span className="font-mono text-[11px]">{new Date(a.timestamp).toLocaleString()}</span>
                                    </div>
                                    <p className="text-zinc-300 leading-relaxed">{a.details}</p>
                                    <span className="text-[10px] font-mono text-zinc-500 block">Actor: {a.actor}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* 2. RISK CALCULATOR DRILL-DOWN VIEW */}
                      {slideoverType === 'risk_calc' && slideoverDetail.risk_calc_detail && (
                        <div className="space-y-6">
                          {/* Provenance Metadata */}
                          <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-3">
                            <div className="flex justify-between items-center">
                              <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wide">
                                Calculation Provenance
                              </span>
                              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-500/30">
                                5,000 Beta-PERT Iterations
                              </span>
                            </div>
                            <div className="text-xs text-zinc-300 space-y-1">
                              <p><strong>Methodology:</strong> {slideoverDetail.risk_calc_detail.provenance.methodology}</p>
                              <p><strong>Distribution:</strong> Beta-PERT 4-parameter with shape α=4 (FAIR standard)</p>
                              <p><strong>Seed:</strong> {slideoverDetail.risk_calc_detail.provenance.seed} (deterministic & reproducible)</p>
                              <p className="font-mono text-zinc-400 text-[11px]">Timestamp: {slideoverDetail.risk_calc_detail.provenance.timestamp}</p>
                            </div>
                          </div>

                          {/* Underlying Scenario Inputs */}
                          <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-3">
                            <h5 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-2">
                              <span>⚙️</span> Underlying Scenario Inputs
                            </h5>
                            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                              <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-zinc-400 text-[10px] block uppercase">Threat Event Freq (TEF)</span>
                                <span className="text-sm font-medium text-white">{slideoverDetail.risk_calc_detail.scenario_inputs.threat_event_frequency} / year</span>
                              </div>
                              <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-zinc-400 text-[10px] block uppercase">Vuln / Control Failure</span>
                                <span className="text-sm font-medium text-amber-300">{slideoverDetail.risk_calc_detail.scenario_inputs.vulnerability_score}</span>
                              </div>
                              <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-zinc-400 text-[10px] block uppercase">Primary Direct Loss</span>
                                <span className="text-sm font-medium text-white">{formatCurrency(slideoverDetail.risk_calc_detail.scenario_inputs.primary_loss_usd)}</span>
                              </div>
                              <div className="p-3 bg-zinc-900 rounded-lg border border-zinc-800">
                                <span className="text-zinc-400 text-[10px] block uppercase">Secondary Liability Loss</span>
                                <span className="text-sm font-medium text-white">{formatCurrency(slideoverDetail.risk_calc_detail.scenario_inputs.secondary_loss_usd)}</span>
                              </div>
                            </div>
                          </div>

                          {/* Monte Carlo Percentile Confidence Bands */}
                          <div className="p-5 bg-zinc-950 rounded-xl border border-zinc-800 space-y-4">
                            <h5 className="text-xs font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-2">
                              <span>📊</span> Empirical Monte Carlo Bands (80% CI)
                            </h5>

                            {/* Inherent ALE Band Breakdown */}
                            {slideoverDetail.risk_calc_detail.confidence_bands?.inherent_ale_band && (
                              <div className="p-3.5 bg-zinc-900 rounded-xl border border-zinc-800 text-xs space-y-2 font-mono">
                                <span className="text-zinc-300 font-semibold block">Inherent ALE (Annualized Loss Exposure):</span>
                                <div className="grid grid-cols-5 gap-2 text-center text-[11px]">
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">MIN</span>
                                    <span className="text-white">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.inherent_ale_band.min)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">P10</span>
                                    <span className="text-rose-300">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.inherent_ale_band.p10)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded border border-zinc-800">
                                    <span className="text-indigo-300 block text-[9px] font-medium">P50 (MEDIAN)</span>
                                    <span className="text-rose-200 font-medium">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.inherent_ale_band.p50)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">P90</span>
                                    <span className="text-rose-300">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.inherent_ale_band.p90)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">MAX</span>
                                    <span className="text-white">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.inherent_ale_band.max)}</span>
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Residual ALE Band Breakdown */}
                            {slideoverDetail.risk_calc_detail.confidence_bands?.residual_ale_band && (
                              <div className="p-3.5 bg-zinc-900 rounded-xl border border-zinc-800 text-xs space-y-2 font-mono">
                                <span className="text-zinc-300 font-semibold block">Residual ALE (Post-Control Mitigation):</span>
                                <div className="grid grid-cols-5 gap-2 text-center text-[11px]">
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">MIN</span>
                                    <span className="text-white">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.residual_ale_band.min)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">P10</span>
                                    <span className="text-emerald-300">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.residual_ale_band.p10)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded border border-emerald-500/30">
                                    <span className="text-indigo-300 block text-[9px] font-medium">P50 (MEDIAN)</span>
                                    <span className="text-emerald-200 font-medium">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.residual_ale_band.p50)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">P90</span>
                                    <span className="text-emerald-300">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.residual_ale_band.p90)}</span>
                                  </div>
                                  <div className="bg-zinc-950 p-2 rounded">
                                    <span className="text-zinc-400 block text-[9px]">MAX</span>
                                    <span className="text-white">{formatCurrency(slideoverDetail.risk_calc_detail.confidence_bands.residual_ale_band.max)}</span>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="text-center py-16 text-zinc-500 text-sm">
                      Record details unavailable.
                    </div>
                  )}
                </div>

                {/* Read-Only Footer */}
                <div className="p-4 bg-zinc-950/95 border-t border-zinc-800 flex items-center justify-between text-xs text-zinc-400 sticky bottom-0 z-20">
                  <span>Read-Only Drill-Down View</span>
                  <button
                    type="button"
                    onClick={handleCloseDrilldown}
                    className="px-4 py-2 bg-zinc-800/50 hover:bg-zinc-800 text-white font-semibold rounded-lg transition-colors"
                  >
                    Close Panel
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Footer */}
          <footer className="border-t border-zinc-800 pt-6 text-center text-xs text-zinc-500">
            CyberGuard AI Platform — Continuous Cyber Risk Quantification & Investment Optimization
          </footer>
        </div>
      );
    }

export default App;
