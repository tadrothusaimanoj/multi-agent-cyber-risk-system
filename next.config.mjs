import { PHASE_DEVELOPMENT_SERVER } from 'next/constants.js';

/** @type {import('next').NextConfig} */
export default (phase) => {
  const isDev = phase === PHASE_DEVELOPMENT_SERVER;
  
  const config = {
    distDir: 'out',
  };

  // Only use static export in production builds
  if (!isDev) {
    config.output = 'export';
  }

  // Only use rewrites in development server
  if (isDev) {
    config.rewrites = async () => {
      return [
        {
          source: '/optimize',
          destination: 'http://127.0.0.1:8000/optimize',
        },
        {
          source: '/risk-summary',
          destination: 'http://127.0.0.1:8000/risk-summary',
        },
        {
          source: '/ingest',
          destination: 'http://127.0.0.1:8000/ingest',
        },
        {
          source: '/findings',
          destination: 'http://127.0.0.1:8000/findings',
        },
        {
          source: '/assets',
          destination: 'http://127.0.0.1:8000/assets',
        },
        {
          source: '/remediations',
          destination: 'http://127.0.0.1:8000/remediations',
        },
        {
          source: '/frameworks',
          destination: 'http://127.0.0.1:8000/frameworks',
        },
        {
          source: '/executive-summary',
          destination: 'http://127.0.0.1:8000/executive-summary',
        },
        {
          source: '/risk-calculator',
          destination: 'http://127.0.0.1:8000/risk-calculator',
        },
        {
          source: '/compliance-gap',
          destination: 'http://127.0.0.1:8000/compliance-gap',
        },
        {
          source: '/audit-trail',
          destination: 'http://127.0.0.1:8000/audit-trail',
        },
        {
          source: '/policy-mapping',
          destination: 'http://127.0.0.1:8000/policy-mapping',
        },
        {
          source: '/scenario-analysis',
          destination: 'http://127.0.0.1:8000/scenario-analysis',
        },
        {
          source: '/mitre-evaluation',
          destination: 'http://127.0.0.1:8000/mitre-evaluation',
        },
        {
          source: '/query-agent/:path*',
          destination: 'http://127.0.0.1:8000/query-agent/:path*',
        },
        {
          source: '/drilldown/:path*',
          destination: 'http://127.0.0.1:8000/drilldown/:path*',
        }
      ];
    };
  }

  return config;
};
