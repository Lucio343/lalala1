// =============================================================================
// Менеджер правил ИАС БИ — Java
// Компиляция: javac RuleManager.java
// Запуск: java RuleManager
// =============================================================================

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

public class RuleManager {
    
    private final Path rulesDir;
    private final List<Rule> rules = new ArrayList<>();
    
    public static class Rule {
        public String name;
        public String category;
        public double riskScore;
        public List<String> recommendations;
        public String version;
        
        public Rule(String name, String category, double riskScore, 
                    List<String> recommendations, String version) {
            this.name = name;
            this.category = category;
            this.riskScore = riskScore;
            this.recommendations = recommendations;
            this.version = version;
        }
        
        @Override
        public String toString() {
            return String.format("[%s] %s (risk=%.1f, v=%s)", 
                category, name, riskScore, version);
        }
    }
    
    public RuleManager(String rulesDir) {
        this.rulesDir = Paths.get(rulesDir);
    }
    
    /** Загрузка правил из директории */
    public void loadRules() throws IOException {
        if (!Files.exists(rulesDir)) {
            Files.createDirectories(rulesDir);
        }
        
        List<Path> yamlFiles = Files.list(rulesDir)
            .filter(p -> p.toString().endsWith(".yaml") || p.toString().endsWith(".yml"))
            .collect(Collectors.toList());
        
        for (Path file : yamlFiles) {
            parseRuleFile(file);
        }
        
        System.out.println("Загружено правил: " + rules.size());
    }
    
    /** Упрощённый парсер YAML (для демонстрации) */
    private void parseRuleFile(Path file) throws IOException {
        List<String> lines = Files.readAllLines(file);
        String currentName = null;
        String currentCategory = null;
        double currentRisk = 0;
        List<String> currentRecs = new ArrayList<>();
        
        for (String line : lines) {
            line = line.trim();
            if (line.startsWith("- name:")) {
                if (currentName != null) {
                    rules.add(new Rule(currentName, currentCategory, currentRisk, 
                        new ArrayList<>(currentRecs), "1.0"));
                }
                currentName = line.substring(7).trim().replace("\"", "");
                currentRecs.clear();
            } else if (line.startsWith("category:")) {
                currentCategory = line.substring(9).trim().replace("\"", "");
            } else if (line.startsWith("risk_score:")) {
                currentRisk = Double.parseDouble(line.substring(11).trim());
            } else if (line.startsWith("- \"") && line.endsWith("\"")) {
                currentRecs.add(line.substring(3, line.length() - 1));
            }
        }
        
        if (currentName != null) {
            rules.add(new Rule(currentName, currentCategory, currentRisk, 
                new ArrayList<>(currentRecs), "1.0"));
        }
    }
    
    /** Добавление нового правила */
    public void addRule(Rule rule) throws IOException {
        rules.add(rule);
        saveRule(rule);
        System.out.println("Добавлено правило: " + rule);
    }
    
    /** Сохранение правила в файл */
    private void saveRule(Rule rule) throws IOException {
        String filename = rule.name.replaceAll("\\s+", "_").toLowerCase() + ".yaml";
        Path file = rulesDir.resolve(filename);
        
        StringBuilder sb = new StringBuilder();
        sb.append("- name: \"").append(rule.name).append("\"\n");
        sb.append("  category: \"").append(rule.category).append("\"\n");
        sb.append("  risk_score: ").append(rule.riskScore).append("\n");
        sb.append("  recommendations:\n");
        for (String rec : rule.recommendations) {
            sb.append("    - \"").append(rec).append("\"\n");
        }
        
        Files.write(file, sb.toString().getBytes());
    }
    
    /** Список всех правил */
    public void listRules() {
        System.out.println("\n=== Все правила ===");
        rules.forEach(System.out::println);
    }
    
    /** Поиск правил по категории */
    public List<Rule> findByCategory(String category) {
        return rules.stream()
            .filter(r -> r.category.equals(category))
            .collect(Collectors.toList());
    }
    
    public static void main(String[] args) throws IOException {
        RuleManager manager = new RuleManager("./rules");
        manager.loadRules();
        manager.listRules();
        
        // Пример добавления нового правила
        manager.addRule(new Rule(
            "Открытый RDP",
            "unauthorized_access",
            8.5,
            Arrays.asList("Закрыть порт 3389", "Использовать VPN"),
            "1.0"
        ));
        
        // Поиск по категории
        System.out.println("\n=== Правила категории 'unauthorized_access' ===");
        manager.findByCategory("unauthorized_access").forEach(System.out::println);
    }
}
