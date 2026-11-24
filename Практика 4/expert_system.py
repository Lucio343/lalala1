"""
Экспертная система принятия решений об инцидентах ИБ.
Правила вынесены в YAML-файл.
"""

import yaml
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class Incident:
    detected: bool
    risk_score: float
    category: str
    recommendations: List[str]
    triggering_findings: List[Dict]


class ExpertSystem:
    """Движок экспертной системы на основе правил."""
    
    def __init__(self, rules_path: str):
        with open(rules_path, 'r', encoding='utf-8') as f:
            self.rules = yaml.safe_load(f)
    
    def evaluate(self, findings: List[Dict]) -> Incident:
        """Оценка findings и вывод об инциденте."""
        triggered = []
        risk_score = 0.0
        categories = set()
        recommendations = set()
        
        for rule in self.rules['rules']:
            if self._matches(rule, findings):
                triggered.append({
                    'rule': rule['name'],
                    'findings': self._get_matching_findings(rule, findings),
                })
                risk_score = max(risk_score, rule['risk_score'])
                categories.add(rule['category'])
                recommendations.update(rule.get('recommendations', []))
        
        detected = risk_score >= self.rules['threshold']
        
        return Incident(
            detected=detected,
            risk_score=risk_score,
            category=', '.join(categories) if categories else 'none',
            recommendations=list(recommendations),
            triggering_findings=triggered,
        )
    
    def _matches(self, rule: Dict, findings: List[Dict]) -> bool:
        """Проверка, срабатывает ли правило."""
        conditions = rule['conditions']
        
        for f in findings:
            if all(self._check_condition(f, c) for c in conditions):
                return True
        return False
    
    def _check_condition(self, finding: Dict, condition: Dict) -> bool:
        """Проверка одного условия."""
        field = condition['field']
        operator = condition['operator']
        value = condition['value']
        
        actual = finding.get(field)
        if actual is None:
            return False
        
        if operator == 'eq':
            return actual == value
        elif operator == 'in':
            return actual in value
        elif operator == 'gte':
            return actual >= value
        elif operator == 'contains':
            return value.lower() in str(actual).lower()
        return False
    
    def _get_matching_findings(self, rule: Dict, findings: List[Dict]) -> List[Dict]:
        """Возвращает findings, которые сработали для правила."""
        result = []
        for f in findings:
            if all(self._check_condition(f, c) for c in rule['conditions']):
                result.append(f)
        return result
