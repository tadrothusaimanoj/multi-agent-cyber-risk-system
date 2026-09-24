"""
COMPLIANCE AGENT: RAG Pipeline for Control Mapping

Retrieval-Augmented Generation pipeline using:
- sentence-transformers/all-MiniLM-L6-v2 for embeddings
- ChromaDB for vector storage
- Ollama (Llama 3.1 8B) or Claude API for LLM
- Strict hallucination guardrails with citation requirements

Maps technical controls to:
- NIST CSF 2.0 (Cybersecurity Framework)
- ISO 27001:2022 Annex A

Author: Senior GRC Specialist
"""

import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from langchain_ollama import ChatOllama
from langchain_anthropic import ChatAnthropic
from langchain.prompts import ChatPromptTemplate
from langchain.schema import Document
import psycopg2
from psycopg2.extras import Json
from loguru import logger


@dataclass
class ControlMapping:
    """Compliance control mapping result"""
    vuln_id: str
    framework: str  # NIST_CSF_2.0 or ISO_27001
    control_id: str
    control_title: str
    mapping_confidence: float  # 0.0 to 1.0
    llm_citation: str  # Exact clause/section referenced
    reasoning: str


# ===== COMPLIANCE KNOWLEDGE BASE =====

NIST_CSF_2_0_CONTROLS = [
    {
        "id": "ID.RA-1",
        "title": "Vulnerabilities in assets are identified, validated, and recorded",
        "function": "IDENTIFY",
        "category": "Risk Assessment",
        "description": "Organizations identify and document vulnerabilities in their information systems and assets through vulnerability scanning, penetration testing, and threat intelligence."
    },
    {
        "id": "ID.RA-2",
        "title": "Cyber threat intelligence is received from information sharing forums and sources",
        "function": "IDENTIFY",
        "category": "Risk Assessment",
        "description": "Gather and analyze threat intelligence from external sources to understand emerging threats."
    },
    {
        "id": "PR.IP-12",
        "title": "A vulnerability management plan is developed and implemented",
        "function": "PROTECT",
        "category": "Information Protection Processes",
        "description": "Establish processes for identifying, assessing, and remediating vulnerabilities on a continuous basis."
    },
    {
        "id": "DE.CM-8",
        "title": "Vulnerability scans are performed",
        "function": "DETECT",
        "category": "Continuous Monitoring",
        "description": "Conduct regular vulnerability assessments to identify security weaknesses."
    },
    {
        "id": "RS.MI-3",
        "title": "Newly identified vulnerabilities are mitigated or documented as accepted risks",
        "function": "RESPOND",
        "category": "Mitigation",
        "description": "Address vulnerabilities through remediation, mitigation, or formal risk acceptance."
    },
    {
        "id": "PR.DS-6",
        "title": "Integrity checking mechanisms are used to verify software, firmware, and information integrity",
        "function": "PROTECT",
        "category": "Data Security",
        "description": "Use cryptographic hashing and digital signatures to ensure system integrity."
    },
    {
        "id": "PR.AC-5",
        "title": "Network integrity is protected (e.g., network segregation, network segmentation)",
        "function": "PROTECT",
        "category": "Access Control",
        "description": "Implement network segmentation and isolation to contain security breaches."
    },
]

ISO_27001_CONTROLS = [
    {
        "id": "A.5.1",
        "title": "Policies for information security",
        "domain": "Organizational Controls",
        "description": "A set of policies for information security shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties."
    },
    {
        "id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "domain": "Technological Controls",
        "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken."
    },
    {
        "id": "A.8.7",
        "title": "Protection against malware",
        "domain": "Technological Controls",
        "description": "Protection against malware shall be implemented and supported by appropriate user awareness."
    },
    {
        "id": "A.5.23",
        "title": "Information security for use of cloud services",
        "domain": "Organizational Controls",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements."
    },
    {
        "id": "A.8.9",
        "title": "Configuration management",
        "domain": "Technological Controls",
        "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed."
    },
    {
        "id": "A.8.16",
        "title": "Monitoring activities",
        "domain": "Technological Controls",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents."
    },
]


class ComplianceRAGPipeline:
    """
    RAG pipeline for mapping vulnerabilities to compliance controls.
    """
    
    def __init__(
        self,
        use_ollama: bool = True,
        ollama_model: str = "llama3.1:8b",
        anthropic_api_key: Optional[str] = None
    ):
        """
        Args:
            use_ollama: Use local Ollama (True) or Claude API (False)
            ollama_model: Ollama model name
            anthropic_api_key: Claude API key (if not using Ollama)
        """
        logger.info("Initializing Compliance RAG Pipeline")
        
        # Initialize embedding model
        logger.info("Loading sentence-transformers/all-MiniLM-L6-v2")
        self.embedding_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
        
        # Initialize ChromaDB
        logger.info("Initializing ChromaDB vector store")
        self.chroma_client = chromadb.Client(Settings(
            anonymized_telemetry=False,
            allow_reset=True
        ))
        
        # Create collections
        self.nist_collection = self.chroma_client.get_or_create_collection(
            name="nist_csf_2_0",
            metadata={"description": "NIST Cybersecurity Framework 2.0 controls"}
        )
        
        self.iso_collection = self.chroma_client.get_or_create_collection(
            name="iso_27001",
            metadata={"description": "ISO 27001:2022 Annex A controls"}
        )
        
        # Populate knowledge base
        self._populate_vector_store()
        
        # Initialize LLM
        if use_ollama:
            logger.info(f"Initializing Ollama with model: {ollama_model}")
            self.llm = ChatOllama(
                model=ollama_model,
                temperature=0.1,  # Low temperature for factual responses
            )
        else:
            if not anthropic_api_key:
                raise ValueError("anthropic_api_key required when use_ollama=False")
            logger.info("Initializing Claude API")
            self.llm = ChatAnthropic(
                model="claude-3-5-sonnet-20241022",
                api_key=anthropic_api_key,
                temperature=0.1
            )
    
    def _populate_vector_store(self):
        """Load compliance controls into ChromaDB"""
        logger.info("Populating vector store with compliance controls")
        
        # NIST CSF 2.0
        if self.nist_collection.count() == 0:
            nist_texts = [
                f"{c['id']}: {c['title']}. {c['description']}"
                for c in NIST_CSF_2_0_CONTROLS
            ]
            nist_embeddings = self.embedding_model.encode(nist_texts).tolist()
            
            self.nist_collection.add(
                embeddings=nist_embeddings,
                documents=nist_texts,
                ids=[c['id'] for c in NIST_CSF_2_0_CONTROLS],
                metadatas=[
                    {
                        'title': c['title'],
                        'function': c['function'],
                        'category': c['category']
                    }
                    for c in NIST_CSF_2_0_CONTROLS
                ]
            )
            logger.info(f"Loaded {len(NIST_CSF_2_0_CONTROLS)} NIST CSF 2.0 controls")
        
        # ISO 27001
        if self.iso_collection.count() == 0:
            iso_texts = [
                f"{c['id']}: {c['title']}. {c['description']}"
                for c in ISO_27001_CONTROLS
            ]
            iso_embeddings = self.embedding_model.encode(iso_texts).tolist()
            
            self.iso_collection.add(
                embeddings=iso_embeddings,
                documents=iso_texts,
                ids=[c['id'] for c in ISO_27001_CONTROLS],
                metadatas=[
                    {
                        'title': c['title'],
                        'domain': c['domain']
                    }
                    for c in ISO_27001_CONTROLS
                ]
            )
            logger.info(f"Loaded {len(ISO_27001_CONTROLS)} ISO 27001 controls")
    
    def retrieve_relevant_controls(
        self,
        query: str,
        framework: str,
        top_k: int = 3
    ) -> List[Dict]:
        """
        Retrieve most relevant controls via semantic search.
        
        Args:
            query: Vulnerability description or technical control
            framework: 'NIST_CSF_2.0' or 'ISO_27001'
            top_k: Number of controls to retrieve
            
        Returns:
            List of relevant controls with metadata
        """
        collection = (
            self.nist_collection if framework == 'NIST_CSF_2.0'
            else self.iso_collection
        )
        
        # Generate query embedding
        query_embedding = self.embedding_model.encode([query]).tolist()[0]
        
        # Semantic search
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k
        )
        
        controls = []
        for i in range(len(results['ids'][0])):
            controls.append({
                'id': results['ids'][0][i],
                'document': results['documents'][0][i],
                'metadata': results['metadatas'][0][i],
                'distance': results['distances'][0][i] if 'distances' in results else None
            })
        
        return controls
    
    def map_vulnerability_to_controls(
        self,
        vuln_id: str,
        vuln_description: str,
        frameworks: List[str] = ['NIST_CSF_2.0', 'ISO_27001']
    ) -> List[ControlMapping]:
        """
        Map a vulnerability to relevant compliance controls using RAG.
        
        Args:
            vuln_id: CVE identifier
            vuln_description: Detailed vulnerability description
            frameworks: List of frameworks to map against
            
        Returns:
            List of control mappings with citations
        """
        logger.info(f"Mapping {vuln_id} to compliance controls")
        
        all_mappings = []
        
        for framework in frameworks:
            # Retrieve top 3 relevant controls
            relevant_controls = self.retrieve_relevant_controls(
                query=vuln_description,
                framework=framework,
                top_k=3
            )
            
            # Build context for LLM
            context = "\n\n".join([
                f"Control {c['id']}: {c['document']}"
                for c in relevant_controls
            ])
            
            # Prompt with strict citation requirements
            prompt = ChatPromptTemplate.from_messages([
                ("system", """You are a senior GRC analyst mapping cybersecurity vulnerabilities to compliance controls.

CRITICAL REQUIREMENTS:
1. You MUST cite the exact control ID (e.g., "ID.RA-1" or "A.8.8") for every mapping
2. You MUST only map to controls provided in the context - DO NOT hallucinate controls
3. If no relevant control exists, respond with "NO_MAPPING"
4. Provide a confidence score (0.0 to 1.0) based on relevance
5. Explain your reasoning in 1-2 sentences

Output Format (JSON):
{{
  "control_id": "ID.RA-1",
  "confidence": 0.95,
  "reasoning": "This vulnerability requires identification and validation, directly aligning with ID.RA-1."
}}"""),
                ("user", f"""Vulnerability: {vuln_id}
Description: {vuln_description}

Relevant {framework} Controls:
{context}

Map this vulnerability to the MOST relevant control. Output ONLY valid JSON.""")
            ])
            
            try:
                response = self.llm.invoke(prompt.format_messages())
                response_text = response.content.strip()
                
                # Parse LLM response
                import json
                try:
                    mapping_data = json.loads(response_text)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse LLM response for {framework}: {response_text}")
                    continue
                
                if mapping_data.get('control_id') == 'NO_MAPPING':
                    logger.info(f"No relevant {framework} control found for {vuln_id}")
                    continue
                
                # Validate citation against retrieved controls
                control_ids = [c['id'] for c in relevant_controls]
                if mapping_data['control_id'] not in control_ids:
                    logger.warning(
                        f"LLM cited non-existent control {mapping_data['control_id']} - HALLUCINATION DETECTED"
                    )
                    continue
                
                # Get full control details
                cited_control = next(
                    c for c in relevant_controls
                    if c['id'] == mapping_data['control_id']
                )
                
                mapping = ControlMapping(
                    vuln_id=vuln_id,
                    framework=framework,
                    control_id=mapping_data['control_id'],
                    control_title=cited_control['metadata'].get('title', ''),
                    mapping_confidence=float(mapping_data.get('confidence', 0.0)),
                    llm_citation=mapping_data['control_id'],
                    reasoning=mapping_data.get('reasoning', '')
                )
                
                all_mappings.append(mapping)
                logger.info(
                    f"Mapped {vuln_id} → {framework} {mapping.control_id} "
                    f"(confidence: {mapping.mapping_confidence:.2f})"
                )
                
            except Exception as e:
                logger.error(f"LLM mapping failed for {framework}: {e}")
                continue
        
        return all_mappings


class ComplianceService:
    """Service layer for compliance mapping persistence"""
    
    def __init__(self, database_url: str, rag_pipeline: ComplianceRAGPipeline):
        self.database_url = database_url
        self.rag = rag_pipeline
    
    def connect_db(self):
        return psycopg2.connect(self.database_url)
    
    def map_and_persist(
        self,
        vuln_id: str,
        vuln_description: str
    ) -> List[ControlMapping]:
        """
        Map vulnerability to controls and save to database.
        """
        mappings = self.rag.map_vulnerability_to_controls(vuln_id, vuln_description)
        
        conn = self.connect_db()
        try:
            with conn.cursor() as cursor:
                for mapping in mappings:
                    cursor.execute("""
                        INSERT INTO compliance_mappings (
                            vuln_id, framework, control_id, control_title,
                            mapping_confidence, llm_citation
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (vuln_id, framework, control_id) DO NOTHING
                    """, (
                        mapping.vuln_id,
                        mapping.framework,
                        mapping.control_id,
                        mapping.control_title,
                        mapping.mapping_confidence,
                        mapping.llm_citation
                    ))
                conn.commit()
                logger.info(f"Persisted {len(mappings)} compliance mappings")
        except Exception as e:
            logger.error(f"Failed to persist mappings: {e}")
            conn.rollback()
        finally:
            conn.close()
        
        return mappings


def main():
    """Standalone testing"""
    from dotenv import load_dotenv
    load_dotenv()
    
    # Initialize RAG pipeline (using Ollama by default)
    rag = ComplianceRAGPipeline(use_ollama=True)
    
    # Test mapping
    vuln_description = """
    Remote code execution vulnerability in Apache Log4j library.
    Attackers can execute arbitrary code by sending crafted JNDI lookup strings.
    Affects Log4j versions 2.0-beta9 through 2.14.1.
    """
    
    mappings = rag.map_vulnerability_to_controls(
        vuln_id='CVE-2021-44228',
        vuln_description=vuln_description
    )
    
    print(f"\n{'='*60}")
    print("COMPLIANCE CONTROL MAPPINGS")
    print(f"{'='*60}")
    for m in mappings:
        print(f"\n{m.framework} {m.control_id}: {m.control_title}")
        print(f"  Confidence: {m.mapping_confidence:.2f}")
        print(f"  Reasoning: {m.reasoning}")
    print(f"\n{'='*60}\n")


if __name__ == '__main__':
    main()
