# Insider Threat Detector - PlantUML Designs

This page contains PlantUML source code for the main design diagrams of the Insider Threat Detector project.

## 1. Rich Picture Diagram

```plantuml
@startuml
title Insider Threat Detector - Rich Picture
left to right direction
skinparam shadowing false
skinparam defaultFontName Arial
skinparam rectangle {
  BackgroundColor #F8FAFC
  BorderColor #334155
}

actor "SOC Analyst" as Analyst
actor "Security Manager" as Manager
actor "Employee / Insider" as Employee
actor "HR Team" as HR

rectangle "Enterprise Activity Sources" as Sources {
  rectangle "SIEM Alerts\nlogon, file, USB, email, web" as SIEM
  rectangle "Mock Alert JSON Files\nbenign and threat samples" as MockAlerts
}

rectangle "Insider Threat Detection Platform" as Platform {
  rectangle "Streamlit Dashboard\nUpload, score breakdown,\nexecutive report" as UI
  rectangle "FastAPI Backend\n/analyze pipeline" as API
  rectangle "Context Enrichment\nHR and incident history" as Enrich
  rectangle "Multi-Agent AI Analysis\nM1, Core, DFuse, M3,\nMistral, Gemini" as Agents
  rectangle "Weighted Scorer\nunified threat index" as Scorer
  rectangle "Report Builder\nverdict and action" as Report
}

database "mock_hr.db\nemployee status,\nPIP, resignation,\nrole, department" as HRDB
database "incident_history.db\npast incidents and\naudit log" as IncidentDB
cloud "Mistral API\nbehavioural reasoning" as Mistral
cloud "Gemini API\nfalse-positive audit" as Gemini
folder "Local Model Files\n.pkl and feature metadata" as Models

Employee --> SIEM : generates activity
MockAlerts --> UI : test event upload
SIEM --> UI : SIEM JSON alert
Analyst --> UI : uploads alert and reviews result
Manager --> UI : reads executive report
HR --> HRDB : maintains employee context

UI --> API : POST /analyze
API --> Enrich : parsed event
Enrich --> HRDB : employee lookup
Enrich --> IncidentDB : incident summary
Enrich --> Agents : enriched event
Agents --> Models : load ML pipelines
Agents --> Mistral : optional LLM call
Agents --> Gemini : optional LLM call
Agents --> Scorer : agent scores
Scorer --> Report : risk level and weights
Report --> IncidentDB : analysis audit entry
Report --> UI : JSON report
UI --> Analyst : gauges, findings, verdict
UI --> Manager : downloadable report

note bottom of Platform
Goal: detect suspicious insider behaviour by combining
ML anomaly/classification signals, HR context,
incident history, and LLM reasoning into one auditable score.
end note
@enduml
```

## 2. High-Level System Architecture

```plantuml
@startuml
title Insider Threat Detector - High-Level System Architecture
left to right direction
skinparam shadowing false
skinparam componentStyle rectangle

actor "SOC Analyst" as Analyst

package "Frontend - Streamlit" {
  [app_streamlit.py\nNavigation Shell] as Shell
  [Upload & Analyze Page] as Upload
  [Score Breakdown Page] as Breakdown
  [Executive Report Page] as ExecReport
  [score_gauge.py] as Gauge
  [model_card.py] as ModelCard
}

package "Backend - FastAPI" {
  [GET /health] as Health
  [POST /analyze] as Analyze
}

package "Pipeline Services" {
  [parser.py\nparse_event] as Parser
  [enrichment.py\nenrich_event] as Enrichment
  [feature_extractor.py\nextract_features] as FeatureExtractor
  [ML Agents] as MLAgents
  [LLM Agents] as LLMAgents
  [scorer.py\ncompute_threat_index] as Scorer
  [report_builder.py\nbuild_report] as ReportBuilder
}

database "mock_hr.db" as HRDB
database "incident_history.db" as IncidentDB
folder "models/\nModel 1, Model 2, Model 3" as ModelFiles
folder "backend/prompts/" as Prompts
cloud "Mistral API" as MistralAPI
cloud "Gemini API" as GeminiAPI
folder "data/mock_alerts/" as MockData

Analyst --> Shell
Shell --> Upload
Shell --> Breakdown
Shell --> ExecReport
Upload --> MockData : optional sample JSON
Upload --> Analyze : HTTP POST event JSON
Breakdown --> Gauge
Breakdown --> ModelCard
ExecReport --> Gauge

Analyze --> Parser
Parser --> Enrichment
Enrichment --> HRDB
Enrichment --> IncidentDB
Enrichment --> FeatureExtractor
FeatureExtractor --> MLAgents
Enrichment --> LLMAgents
MLAgents --> ModelFiles
LLMAgents --> Prompts
LLMAgents --> MistralAPI
LLMAgents --> GeminiAPI
MLAgents --> Scorer
LLMAgents --> Scorer
Scorer --> ReportBuilder
ReportBuilder --> IncidentDB : log_analysis()
ReportBuilder --> Upload : report JSON response
Health --> Analyst : service status
@enduml
```

## 3. Component Diagram

```plantuml
@startuml
title Insider Threat Detector - Component Diagram

left to right direction

skinparam shadowing false
skinparam componentStyle rectangle
skinparam linetype ortho
skinparam roundcorner 10
skinparam dpi 180
skinparam nodesep 70
skinparam ranksep 80
skinparam defaultFontName "Segoe UI"

skinparam package {
    BackgroundColor #F8FAFC
    BorderColor #CBD5E1
    FontStyle bold
}

skinparam component {
    BackgroundColor White
    BorderColor #2563EB
    BorderThickness 2
}

skinparam database {
    BackgroundColor #ECFDF5
    BorderColor #16A34A
}

skinparam folder {
    BackgroundColor #FFF7ED
    BorderColor #EA580C
}

skinparam cloud {
    BackgroundColor #EEF2FF
    BorderColor #4F46E5
}

actor "SOC Analyst" as Analyst

'====================================================
' Frontend
'====================================================

package "Frontend (Streamlit)" {

component "Navigation Shell\napp_streamlit.py" as FEApp

component "Upload & Analyze\nUpload_&_Analyze.py" as Upload

component "Threat Score Dashboard\nScore_Breakdown.py" as Dashboard

component "Executive Report\nExecutive_Report.py" as Executive

component "Score Gauge\nscore_gauge.py" as Gauge

component "Model Card\nmodel_card.py" as Card

FEApp --> Upload
FEApp --> Dashboard
FEApp --> Executive

Dashboard --> Gauge
Dashboard --> Card

Executive --> Gauge

}

'====================================================
' Backend
'====================================================

package "Backend (FastAPI)" {

component "REST API\napp.py" as API

component "Event Parser\nparser.py" as Parser

component "Context Enrichment\nenrichment.py" as Enrichment

component "Feature Extraction\nfeature_extractor.py" as Features

component "Risk Scoring\nscorer.py" as Scorer

component "Report Builder\nreport_builder.py" as Report

component "Database Utilities\ndb_utils.py" as DB

API --> Parser
Parser --> Enrichment
Enrichment --> Features
Features --> Scorer
Scorer --> Report

}

'====================================================
' AI Services
'====================================================

package "AI Components" {

package "Machine Learning Agents" {

component "Model 1 Agent\nml_agent_m1.py" as M1

component "Core Agent\nml_agent_core.py" as CORE

component "DFuse Agent\nml_agent_dfuse.py" as DFUSE

component "Model 3 Agent\nml_agent_m3.py" as M3

}

package "LLM Agents" {

component "Mistral Agent\nllm_agent_mistral.py" as MISTRAL

component "Gemini Agent\nllm_agent_gemini.py" as GEMINI

}

}

'====================================================
' Prompt Management
'====================================================

package "Prompt Management" {

component "Prompt Loader\nprompt_loader.py" as Loader

file "mistral_threat_analysis.txt" as MPrompt

file "gemini_second_opinion.txt" as GPrompt

Loader --> MPrompt
Loader --> GPrompt

}

'====================================================
' Data Layer
'====================================================

package "Data Layer" {

database "Employee Context DB" as HRDB

database "Incident Repository" as IncidentDB

folder "Model Repository\nModel 1" as Model1

folder "Model Repository\nModel 2" as Model2

folder "Model Repository\nModel 3" as Model3

}

'====================================================
' External Services
'====================================================

package "External AI Services" {

cloud "Mistral API" as MistralAPI

cloud "Gemini API" as GeminiAPI

}

'====================================================
' User Interaction
'====================================================

Analyst --> FEApp

Upload --> API : POST /analyze

'====================================================
' Pipeline
'====================================================

Features --> M1
Features --> CORE
Features --> DFUSE
Features --> M3

M1 --> Scorer
CORE --> Scorer
DFUSE --> Scorer
M3 --> Scorer

Enrichment --> MISTRAL
Enrichment --> GEMINI

MISTRAL --> Scorer
GEMINI --> Scorer

Scorer --> Report

Report --> Upload : JSON Response

'====================================================
' Database
'====================================================

Enrichment --> DB

Report --> DB

DB --> HRDB

DB --> IncidentDB

'====================================================
' Models
'====================================================

M1 --> Model1

CORE --> Model2

DFUSE --> Model2

M3 --> Model3

'====================================================
' Prompt Files
'====================================================

MISTRAL --> Loader

GEMINI --> Loader

'====================================================
' External APIs
'====================================================

MISTRAL --> MistralAPI

GEMINI --> GeminiAPI

@enduml
```

## 4. Class Diagram

```plantuml
@startuml
title Insider Threat Detector - Clean Class Diagram

skinparam shadowing false
skinparam classAttributeIconSize 0
skinparam linetype ortho
skinparam roundcorner 10
skinparam dpi 180
skinparam defaultFontName "Segoe UI"

'=============================
' Core Data Model
'=============================
package "Domain Model" {

class LogEvent {
  +user_id: str
  +event_type: str
  +timestamp: str
  +action: str
  +source_ip: str
  +destination: str
  +bytes_transferred: int
  +after_hours: bool
  +device_id: str
  +extra: dict
}

class AnalyzeRequest {
  +event: dict | str
}

LogEvent <.. AnalyzeRequest : contains
}

'=============================
' Data Processing Layer
'=============================
package "Data Processing Layer" {

class Parser {
  +parse_event(raw_input): LogEvent
}

class EnrichmentEngine {
  +enrich_event(user_id, event): dict
}

class FeatureExtractor {
  +FEATURE_ORDER: list
  +extract_features(event, enriched): ndarray
}

Parser --> LogEvent
FeatureExtractor --> LogEvent
FeatureExtractor --> EnrichmentEngine
EnrichmentEngine --> LogEvent
}

'=============================
' AI / ML Layer
'=============================
package "AI / ML Layer" {

abstract class MLAgent {
  +predict(features, context): dict
}

class MLAgentM1
class MLAgentCore
class MLAgentDFuse
class MLAgentM3

MLAgent <|-- MLAgentM1
MLAgent <|-- MLAgentCore
MLAgent <|-- MLAgentDFuse
MLAgent <|-- MLAgentM3

class MistralAgent {
  +analyze(enriched_event): dict
}

class GeminiAgent {
  +analyze(enriched_event, prior_scores): dict
}

MistralAgent --> EnrichmentEngine
GeminiAgent --> EnrichmentEngine
}

'=============================
' Scoring Layer
'=============================
package "Decision Layer" {

class Scorer {
  +WEIGHTS: dict
  +RISK_THRESHOLDS: dict
  +compute_threat_index(scores): dict
}

class ReportBuilder {
  +build_report(event, enriched, scores, outputs): dict
}

Scorer --> MLAgent
Scorer --> MistralAgent
Scorer --> GeminiAgent

ReportBuilder --> Scorer
}
 
'=============================
' Persistence Layer
'=============================
package "Persistence Layer" {

class DBUtils {
  +get_employee(id): dict
  +get_incident_summary(id): dict
  +insert_incident(data): int
  +log_analysis(data): bool
}

DBUtils --> LogEvent
}

'=============================
' Relationships (Clean Flow)
'=============================

AnalyzeRequest --> Parser
Parser --> EnrichmentEngine
EnrichmentEngine --> FeatureExtractor

FeatureExtractor --> MLAgent
FeatureExtractor --> MistralAgent
FeatureExtractor --> GeminiAgent

MLAgent --> Scorer
MistralAgent --> Scorer
GeminiAgent --> Scorer

Scorer --> ReportBuilder
ReportBuilder --> DBUtils

@enduml
```

## 5. Sequence Diagram

```plantuml
@startuml
title Insider Threat Detector - Main Analysis Sequence

' --- Global Styling & Layout ---
skinparam maxMessageSize 200
skinparam shadowing false
skinparam roundcorner 8
skinparam defaultFontName Segoe UI, Helvetica, Arial, sans-serif
autonumber

' --- Modern Color Palette ---
skinparam sequence {
    ArrowColor #2563EB
    LifeLineBorderColor #475569
    LifeLineBackgroundColor #F1F5F9
    ParticipantBorderColor #334155
    ParticipantBackgroundColor #FFFFFF
    ParticipantFontSize 14
    ParticipantFontName bold
}
skinparam database {
    BackgroundColor #F0FDF4
    BorderColor #16A34A
}
skinparam box {
    Padding 10
}

' --- Actors & Grouped Participants ---
actor "SOC Analyst" as Analyst #F1F5F9

box "Presentation Layer" #F8FAFC
    participant "Streamlit UI\n(Upload & Analyze)" as UI
end box

box "Core Backend Engine" #EEF2FF
    participant "FastAPI\n(API Gateway)" as API
    participant "Parser" as Parser
    participant "Enrichment\nEngine" as Enrich
    participant "Feature\nExtractor" as Features
    participant "Scorer" as Scorer
    participant "Report\nBuilder" as Report
end box

box "Databases & Storage" #F0FDF4
    database "mock_hr.db" as HRDB
    database "incident_history.db" as IncidentDB
    database "analysis_audit_log" as Audit
end box

box "AI & ML Engines" #FFF7ED
    participant "ML Agents\n(M1, Core, DFuse, M3)" as ML
    participant "Mistral Agent\n(Reasoning)" as Mistral
    participant "Gemini Agent\n(Audit)" as Gemini
end box

' --- Sequence Flow ---

Analyst -> UI : Upload or paste SIEM JSON
activate UI

UI -> API : POST /analyze {event}
activate API

' 1. Parsing Phase
API -> Parser : parse_event(request.event)
activate Parser
Parser --> API : LogEvent object
deactivate Parser

|||

' 2. Data Enrichment Phase
API -> Enrich : enrich_event(user_id, event)
activate Enrich

Enrich -> HRDB : get_employee(user_id)
HRDB --> Enrich : HR context

Enrich -> IncidentDB : get_incident_summary(user_id)
IncidentDB --> Enrich : incident context

Enrich --> API : enriched_event
deactivate Enrich

|||

' 3. Feature Extraction
API -> Features : extract_features(event, enriched)
activate Features
Features --> API : numeric feature vector
deactivate Features

|||

' 4. AI & ML Analysis Pipeline
API -> ML : predict(features, enriched)
activate ML
ML --> API : four ML scores & findings
deactivate ML

API -> Mistral : analyze(enriched)
activate Mistral
alt API key configured
  Mistral -> Mistral : Call Mistral API & parse JSON
else no key or API error
  Mistral -> Mistral : Synthetic or error fallback
end
Mistral --> API : Mistral score & reasoning
deactivate Mistral

API -> Gemini : analyze(enriched)
activate Gemini
alt API key configured
  Gemini -> Gemini : Call Gemini API & parse JSON
else no key or API error
  Gemini -> Gemini : Synthetic false-positive audit
end
Gemini --> API : Gemini score & audit result
deactivate Gemini

|||

' 5. Scoring & Reporting Phase
API -> Scorer : compute_threat_index(all scores)
activate Scorer
Scorer --> API : unified score, risk level, weights
deactivate Scorer

API -> Report : build_report(event, enriched, score, outputs)
activate Report
Report --> API : final report JSON
deactivate Report

|||

' 6. Auditing & Final Response
API -> Audit : log_analysis(report_id, employee, scores, verdict)
activate Audit
Audit --> API : persisted or skipped on DB error
deactivate Audit

API --> UI : report JSON
deactivate API

UI --> Analyst : Gauges, agent findings, verdict, download
deactivate UI

@enduml
```

## 6. Module Interaction Sequence Diagram

```plantuml
@startuml
title Insider Threat Detector - Module Interaction Sequence

' --- Global Styling & Visual Tweaks ---
skinparam shadowing false
skinparam maxMessageSize 150
skinparam roundcorner 8
skinparam ParticipantPadding 15
skinparam BoxPadding 15
autonumber

' Styling the sequence lines and boxes
skinparam sequence {
    ArrowColor #334155
    LifeLineBorderColor #334155
    LifeLineBackgroundColor #F8FAFC
    GroupBackgroundColor #F8FAFC
    GroupHeaderFontColor #0F172A
    DividerBackgroundColor #E2E8F0
}

' --- Participants Grouped by Subsystem/Folder ---

box "Frontend" #F8FAFC
    participant "Upload_&_Analyze.py" as Upload #FFFFFF
end box

box "API & Core Engine" #F1F5F9
    participant "app.py" as App #FFFFFF
    participant "parser.py" as Parser #FFFFFF
    participant "enrichment.py" as Enrichment #FFFFFF
    participant "feature_extractor.py" as FeatureExtractor #FFFFFF
end box

box "Database Ops" #F0FDF4
    participant "db_utils.py" as DBUtils #E6FFFA
end box

box "ML Agents" #EEF2FF
    participant "ml_agent_m1.py" as M1 #E0E7FF
    participant "ml_agent_core.py" as Core #E0E7FF
    participant "ml_agent_dfuse.py" as DFuse #E0E7FF
    participant "ml_agent_m3.py" as M3 #E0E7FF
end box

box "LLM Agents" #FFFBEB
    participant "llm_agent_mistral.py" as Mistral #FEF3C7
    participant "llm_agent_gemini.py" as Gemini #FEF3C7
end box

box "Scoring & Reporting" #F8FAFC
    participant "scorer.py" as Scorer #FFFFFF
    participant "report_builder.py" as ReportBuilder #FFFFFF
end box

' --- Execution Flow ---

== API Request & Parsing ==
Upload -> App : requests.post(API_URL, json={"event": payload})
activate App

App -> Parser : parse_event(request.event)
activate Parser
Parser --> App : parsed LogEvent
deactivate Parser

|||
== Context Enrichment ==
App -> Enrichment : enrich_event(ev_dict["user_id"], ev_dict)
activate Enrichment

Enrichment -> DBUtils : get_employee(user_id)
activate DBUtils
DBUtils --> Enrichment : employee row\nor default context
deactivate DBUtils

Enrichment -> DBUtils : get_incident_summary(user_id)
activate DBUtils
DBUtils --> Enrichment : incident aggregate
deactivate DBUtils

Enrichment --> App : enriched dict
deactivate Enrichment

|||
== Feature Extraction ==
App -> FeatureExtractor : extract_features(ev_dict, enriched)
activate FeatureExtractor
FeatureExtractor --> App : numpy feature vector
deactivate FeatureExtractor

|||
== ML Model Predictions ==
App -> M1 : predict(features, enriched)
activate M1
M1 --> App : ml_m1 output
deactivate M1

App -> Core : predict(features, enriched)
activate Core
Core --> App : ml_m2_core output
deactivate Core

App -> DFuse : predict(features, enriched)
activate DFuse
DFuse --> App : ml_m2_dfuse output
deactivate DFuse

App -> M3 : predict(features, enriched)
activate M3
M3 --> App : ml_m3 output
deactivate M3

|||
== LLM Agent Analysis ==
App -> Mistral : await analyze(enriched)
activate Mistral
Mistral --> App : llm_mistral output
deactivate Mistral

App -> Gemini : await analyze(enriched)
activate Gemini
Gemini --> App : llm_gemini output
deactivate Gemini

|||
== Scoring & Audit Logging ==
App -> Scorer : compute_threat_index(scores)
activate Scorer
Scorer --> App : scorer_result
deactivate Scorer

App -> ReportBuilder : build_report(event, enriched,\nscorer_result, all outputs)
activate ReportBuilder
ReportBuilder --> App : report dict
deactivate ReportBuilder

App -> DBUtils : log_analysis(report_id, employee_id,\nevent_type, scores)
activate DBUtils
DBUtils --> App : success or handled error
deactivate DBUtils

App --> Upload : report response
deactivate App

@enduml
```

## 7. System Process Flow Chart

```plantuml
@startuml
title Insider Threat Detector - System Process Flow
skinparam shadowing false
skinparam roundcorner 10
skinparam ActivityBackgroundColor #F8FAFC
skinparam ActivityBorderColor #334155
skinparam ArrowColor #475569
skinparam ActivityDiamondBackgroundColor #FEF2F2
skinparam ActivityDiamondBorderColor #991B1B

start

partition "Ingestion & Validation" {
    :SOC analyst uploads JSON\nor pastes SIEM event;
    :Streamlit sends POST /analyze;
    :Parse raw input;
    if (JSON valid?) then (yes)
        :Normalize to LogEvent;
    else (no)
        :Return HTTP 422 error;
        stop
    endif
}

partition "Context Enrichment" {
    :Read HR context & incident history;
    if (Employee exists?) then (yes)
        :Apply employee context (PIP, role, etc.);
    else (no)
        :Apply default safety context;
    endif
    :Extract numeric feature vector;
}

partition "Parallel AI Inference" {
    fork
        :ML: CatBoost\n(Risk Profile);
    fork again
        :ML: Isolation Forest\n(Core Anomaly);
    fork again
        :ML: Isolation Forest\n(Data Fusion);
    fork again
        :ML: Logon Pipeline\n(Behavioural);
    fork again
        :LLM: Mistral\n(Reasoning);
    fork again
        :LLM: Gemini\n(False-Positive Audit);
    end fork
}

partition "Unified Scoring & Verdict" {
    :Normalize & Clamp scores;
    :Apply weighted ensemble;
    :Compute threat index;
    
    if (Score Level) then (>= 0.80)
        :Risk: Critical\nAction: ESCALATE;
    elseif (>= 0.60)
        :Risk: High\nAction: INVESTIGATE;
    elseif (>= 0.40)
        :Risk: Medium\nAction: MONITOR;
    else (no)
        :Risk: Low\nAction: NO ACTION;
    endif
}

partition "Reporting" {
    :Build structured JSON report;
    :Log analysis to audit DB;
    :Return report to UI;
    :Display gauges & findings;
}

stop
@enduml
```

## 8. Database Design (ER Diagram)

```plantuml
@startuml
title Insider Threat Detector - Normalized Relational Schema

' --- Academic Styling ---
skinparam linetype ortho
skinparam shadowing false
hide circle
skinparam entity {
    BackgroundColor #FFFFFF
    BorderColor #2D3436
    HeaderBackgroundColor #F8F9FA
}

' --- Master Data Layer ---
entity "Employees (Master)" as employees << (E,#FF9F1C) >> {
    * employee_id : VARCHAR(50) <<PK>>
    --
    on_pip : BOOLEAN
    resigned : BOOLEAN
    role : VARCHAR(100)
    department : VARCHAR(100)
    clearance_level : ENUM
    remote_worker : BOOLEAN
}

' --- Transactional & Behavioral Layer ---
entity "SIEM_Log_Events" as logevent << (E,#457B9D) >> {
    * event_id : UUID <<PK>>
    --
    * employee_id : VARCHAR(50) <<FK>>
    event_type : VARCHAR(50)
    timestamp : DATETIME
    bytes_transferred : INT
    device_id : VARCHAR(100)
}

entity "Analysis_Audit_Log" as audit << (E,#E76F51) >> {
    * report_id : UUID <<PK>>
    --
    * employee_id : VARCHAR(50) <<FK>>
    * event_id : UUID <<FK>>
    unified_threat_index : FLOAT
    risk_level : ENUM
    ml_ensemble_scores : JSON
    llm_reasoning_summary : TEXT
    processed_at : DATETIME
}

entity "Historical_Incidents" as incidents << (E,#2A9D8F) >> {
    * incident_id : INT <<PK>>
    --
    * employee_id : VARCHAR(50) <<FK>>
    report_id : UUID <<FK>>
    severity : FLOAT
    incident_type : VARCHAR(50)
    false_positive : BOOLEAN
}

' --- Cardinality and Relationships ---
' Notation: ||--o{ (One-to-Many)
employees ||--o{ logevent : "Generates"
employees ||--o{ audit : "Subject to"
employees ||--o{ incidents : "Involved in"
logevent   ||--o| audit : "Analyzed by"
audit      ||--o{ incidents : "Triggers"

@enduml
```
