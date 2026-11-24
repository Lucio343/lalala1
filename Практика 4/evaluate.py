"""
Оценка качества детекции инцидентов.
Precision, Recall, F1-score.
"""

import json
from typing import List, Dict


class DetectorEvaluator:
    """Оценка качества детектора инцидентов."""
    
    def __init__(self):
        self.tp = 0  # True Positive
        self.fp = 0  # False Positive
        self.fn = 0  # False Negative
        self.tn = 0  # True Negative
    
    def add_result(self, predicted: bool, actual: bool):
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1
    
    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0
    
    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
    
    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total > 0 else 0.0
    
    def report(self) -> Dict:
        return {
            'precision': round(self.precision, 4),
            'recall': round(self.recall, 4),
            'f1_score': round(self.f1, 4),
            'accuracy': round(self.accuracy, 4),
            'confusion_matrix': {
                'TP': self.tp, 'FP': self.fp,
                'FN': self.fn, 'TN': self.tn,
            }
        }


# Пример использования
if __name__ == "__main__":
    evaluator = DetectorEvaluator()
    
    # Тестовые данные: (предсказание, реальность)
    test_cases = [
        (True, True),    # TP
        (True, True),    # TP
        (True, False),   # FP
        (False, True),   # FN
        (False, False),  # TN
        (True, True),    # TP
        (False, False),  # TN
    ]
    
    for pred, actual in test_cases:
        evaluator.add_result(pred, actual)
    
    report = evaluator.report()
    print(json.dumps(report, indent=2, ensure_ascii=False))
