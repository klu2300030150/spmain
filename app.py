"""
CyberShield AI - Advanced Security Simulator Backend
Real password vulnerability analysis and social engineering training
"""

from flask import Flask, request, jsonify
import hashlib
import itertools
import string
import time
import re
import math
import random
from collections import Counter

app = Flask(__name__)

# ============================================================================
# REAL PASSWORD VULNERABILITY ANALYSIS
# ============================================================================

class PasswordAnalyzer:
    """Real password vulnerability analysis"""
    
    def __init__(self):
        # Common password lists
        self.common_passwords = set([
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
            'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
            'qazwsx', 'michael', 'football', 'password1', 'password123', 'welcome',
            'jesus', 'ninja', 'mustang', 'password12', 'admin', 'login', 'starwars',
            'hello', 'charlie', 'donald', 'password2', 'admin123', 'root', 'toor',
            'pass', 'test', 'guest', 'master123', 'changeme', 'secret', '123qwe',
            'zxcvbnm', 'asdfgh', '1234567890', '000000', '111111', '121212', '5201314'
        ])
        
        # Keyboard patterns
        self.keyboard_patterns = [
            'qwerty', 'qwertyuiop', 'asdf', 'asdfghjkl', 'zxcv', 'zxcvbnm',
            '1234', '12345', '123456', '1234567', '12345678', '123456789',
            'qazwsx', '!@#$', 'poiuy', 'lkjhg', 'mnbvc'
        ]
        
        # Year patterns
        self.year_patterns = [str(y) for y in range(1950, 2025)]
        
    def analyze_password(self, password):
        """Comprehensive password vulnerability analysis"""
        
        results = {
            'password': '•' * len(password),  # Masked for security
            'length': len(password),
            'vulnerabilities': [],
            'strength_score': 0,
            'attack_vulnerabilities': {},
            'recommendations': [],
            'character_composition': {
                'lowercase': False,
                'uppercase': False,
                'digits': False,
                'symbols': False,
                'unicode': False
            }
        }
        
        # Check character composition
        results['character_composition']['lowercase'] = bool(re.search(r'[a-z]', password))
        results['character_composition']['uppercase'] = bool(re.search(r'[A-Z]', password))
        results['character_composition']['digits'] = bool(re.search(r'[0-9]', password))
        results['character_composition']['symbols'] = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
        results['character_composition']['unicode'] = bool(re.search(r'[^\x00-\x7F]', password))
        
        # Check for common password
        if password.lower() in self.common_passwords:
            results['vulnerabilities'].append({
                'type': 'common_password',
                'severity': 'critical',
                'description': 'Password found in common password database'
            })
            results['attack_vulnerabilities']['common'] = {
                'vulnerable': True,
                'description': 'This is a commonly used password',
                'crack_time': 'Instantly'
            }
        
        # Check for keyboard patterns
        password_lower = password.lower()
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                results['vulnerabilities'].append({
                    'type': 'keyboard_pattern',
                    'severity': 'high',
                    'description': f'Contains keyboard pattern: {pattern}'
                })
                break
        
        # Check for year patterns
        for year in self.year_patterns:
            if year in password:
                results['vulnerabilities'].append({
                    'type': 'year_in_password',
                    'severity': 'medium',
                    'description': f'Contains year {year} - easily guessable'
                })
                break
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            results['vulnerabilities'].append({
                'type': 'repeated_characters',
                'severity': 'medium',
                'description': 'Contains repeated characters'
            })
        
        # Check for sequential characters
        if self._has_sequential(password):
            results['vulnerabilities'].append({
                'type': 'sequential',
                'severity': 'medium',
                'description': 'Contains sequential characters'
            })
        
        # Check for personal info patterns
        if self._has_personal_patterns(password):
            results['vulnerabilities'].append({
                'type': 'personal_info',
                'severity': 'high',
                'description': 'May contain personal information'
            })
        
        # Calculate strength score
        results['strength_score'] = self._calculate_strength(password, results['vulnerabilities'])
        
        # Calculate crack times for different attacks
        results['crack_times'] = self._calculate_crack_times(password)
        
        # Analyze each attack type specifically
        results['attack_vulnerabilities'] = self._analyze_attack_vulnerabilities(
            password, results['vulnerabilities']
        )
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(
            password, results['character_composition'], results['vulnerabilities']
        )
        
        return results
    
    def _has_sequential(self, password):
        """Check for sequential characters"""
        for i in range(len(password) - 2):
            if ord(password[i+1]) - ord(password[i]) == 1 and ord(password[i+2]) - ord(password[i+1]) == 1:
                return True
        return False
    
    def _has_personal_patterns(self, password):
        """Check for personal information patterns"""
        patterns = [
            r'\d{3}-\d{2}-\d{4}',  # SSN
            r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',  # Credit card
            r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)',  # Months
        ]
        return any(re.search(p, password.lower()) for p in patterns)
    
    def _calculate_strength(self, password, vulnerabilities):
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length scoring
        if len(password) >= 16:
            score += 30
        elif len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            score += 5
        
        # Character variety
        char_types = sum([
            bool(re.search(r'[a-z]', password)),
            bool(re.search(r'[A-Z]', password)),
            bool(re.search(r'[0-9]', password)),
            bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))
        ])
        score += char_types * 10
        
        # Length bonus
        if len(password) > 8:
            score += min(20, (len(password) - 8) * 3)
        
        # Deduct for vulnerabilities
        severity_weights = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}
        for vuln in vulnerabilities:
            score -= severity_weights.get(vuln['severity'], 10)
        
        return max(0, min(100, score))
    
    def _calculate_crack_times(self, password):
        """Calculate realistic crack times for different attack methods"""
        
        # Character pool size
        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'[0-9]', password): pool_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password): pool_size += 32
        pool_size = max(pool_size, 1)
        
        # Total combinations
        total_combinations = pool_size ** len(password)
        
        crack_times = {}
        
        # Online attack (100 guesses/sec - realistic throttled)
        online_rate = 100
        crack_times['online_attack'] = self._format_time(total_combinations / online_rate)
        
        # Offline attack (10 billion guesses/sec - modern GPU)
        offline_rate = 10_000_000_000
        crack_times['offline_attack'] = self._format_time(total_combinations / offline_rate)
        
        # Dictionary attack (depends on password being in wordlist)
        if password.lower() in self.common_passwords:
            crack_times['dictionary_attack'] = 'Instant (< 1 second)'
        else:
            crack_times['dictionary_attack'] = self._format_time(len(self.common_passwords))
        
        # Rainbow table (for MD5 hashes)
        if len(password) <= 8:
            crack_times['rainbow_table'] = 'Possible (< 1 minute)'
        else:
            crack_times['rainbow_table'] = 'Not feasible'
        
        # GPU cluster attack
        gpu_rate = 100_000_000_000  # 100 billion/sec
        crack_times['gpu_cluster'] = self._format_time(total_combinations / gpu_rate)
        
        return crack_times
    
    def _format_time(self, seconds):
        """Format seconds into human readable time"""
        if seconds < 0.001:
            return 'Instant'
        elif seconds < 1:
            return 'Less than a second'
        elif seconds < 60:
            return f'{int(seconds)} seconds'
        elif seconds < 3600:
            return f'{int(seconds/60)} minutes'
        elif seconds < 86400:
            return f'{int(seconds/3600)} hours'
        elif seconds < 31536000:
            return f'{int(seconds/86400)} days'
        elif seconds < 31536000 * 1000:
            years = int(seconds/31536000)
            return f'{years} years'
        elif seconds < 31536000 * 1000000:
            return f'{int(seconds/31536000/1000)} thousand years'
        else:
            return 'Millions of years'
    
    def _analyze_attack_vulnerabilities(self, password, vulnerabilities):
        """Analyze vulnerability to each specific attack type"""
        
        attacks = {}
        password_lower = password.lower()
        
        # Brute Force
        attacks['brute_force'] = {
            'vulnerable': len(password) < 12,
            'success_probability': self._calculate_brute_force_prob(password),
            'description': 'Short passwords are vulnerable to brute force',
            'protection': 'Use 12+ characters with mixed types'
        }
        
        # Dictionary Attack
        is_common = password_lower in self.common_passwords
        attacks['dictionary'] = {
            'vulnerable': is_common,
            'success_probability': 1.0 if is_common else 0.001,
            'description': 'Common passwords are instantly cracked',
            'protection': 'Avoid dictionary words and common patterns'
        }
        
        # Rainbow Table
        attacks['rainbow_table'] = {
            'vulnerable': len(password) <= 8 and not re.search(r'[!@#$%^&*()]', password),
            'success_probability': 0.95 if len(password) <= 6 else 0.3 if len(password) <= 8 else 0.01,
            'description': 'Short passwords without symbols are vulnerable',
            'protection': 'Use 9+ characters with special symbols'
        }
        
        # Pattern-based
        has_pattern = any(p in password_lower for p in self.keyboard_patterns)
        attacks['pattern'] = {
            'vulnerable': has_pattern,
            'success_probability': 0.8 if has_pattern else 0.05,
            'description': 'Keyboard patterns are easily guessed',
            'protection': 'Avoid qwerty, 12345, asdf patterns'
        }
        
        # Hybrid Attack
        attacks['hybrid'] = {
            'vulnerable': len(password) < 10 and (has_pattern or is_common),
            'success_probability': 0.7 if (len(password) < 10 and (has_pattern or is_common)) else 0.1,
            'description': 'Combines dictionary words with substitutions',
            'protection': 'Use random characters, not word+number'
        }
        
        # AI/Machine Learning
        attacks['ai_attack'] = {
            'vulnerable': len(password) < 14,
            'success_probability': self._calculate_ai_prob(password),
            'description': 'AI can predict common password patterns',
            'protection': 'Use truly random passwords'
        }
        
        return attacks
    
    def _calculate_brute_force_prob(self, password):
        """Calculate brute force success probability"""
        pool = 0
        if re.search(r'[a-z]', password): pool += 26
        if re.search(r'[A-Z]', password): pool += 26
        if re.search(r'[0-9]', password): pool += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password): pool += 32
        
        combinations = pool ** len(password)
        
        if combinations < 10**9:
            return 0.9
        elif combinations < 10**12:
            return 0.5
        elif combinations < 10**15:
            return 0.2
        else:
            return 0.05
    
    def _calculate_ai_prob(self, password):
        """Calculate AI attack success probability"""
        # AI models can predict common patterns
        password_lower = password.lower()
        
        # Check for common patterns AI can learn
        if password_lower in self.common_passwords:
            return 0.99
        
        # Check for common transformations
        common_transforms = ['123', 'abc', '111', 'aaa', 'xyz']
        if any(t in password_lower for t in common_transforms):
            return 0.7
        
        # Check for personal patterns
        if any(year in password for year in self.year_patterns):
            return 0.6
        
        if len(password) < 10:
            return 0.4
        elif len(password) < 14:
            return 0.2
        else:
            return 0.05
    
    def _generate_recommendations(self, password, composition, vulnerabilities):
        """Generate actionable recommendations"""
        recommendations = []
        
        if len(password) < 12:
            recommendations.append({
                'priority': 'high',
                'text': 'Use at least 12 characters. Length is the most important factor.'
            })
        
        if not composition['uppercase']:
            recommendations.append({
                'priority': 'high',
                'text': 'Add uppercase letters (A-Z)'
            })
        
        if not composition['lowercase']:
            recommendations.append({
                'priority': 'high',
                'text': 'Add lowercase letters (a-z)'
            })
        
        if not composition['digits']:
            recommendations.append({
                'priority': 'medium',
                'text': 'Add numbers (0-9)'
            })
        
        if not composition['symbols']:
            recommendations.append({
                'priority': 'medium',
                'text': 'Add special characters (!@#$%^&*)'
            })
        
        # Check vulnerability types
        vuln_types = [v['type'] for v in vulnerabilities]
        
        if 'common_password' in vuln_types:
            recommendations.append({
                'priority': 'critical',
                'text': 'CRITICAL: This is a commonly used password. Change immediately!'
            })
        
        if 'keyboard_pattern' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'text': 'Avoid keyboard patterns (qwerty, asdf, 1234, etc.)'
            })
        
        if 'year_in_password' in vuln_types:
            recommendations.append({
                'priority': 'medium',
                'text': 'Avoid using years in passwords'
            })
        
        if 'repeated_characters' in vuln_types:
            recommendations.append({
                'priority': 'low',
                'text': 'Avoid repeating characters (aaa, 111)'
            })
        
        # Positive feedback
        if len(password) >= 16 and composition['symbols'] and composition['uppercase'] and composition['lowercase'] and composition['digits']:
            recommendations.append({
                'priority': 'success',
                'text': '✅ Excellent! Your password is very strong.'
            })
        
        return recommendations


# ============================================================================
# EMAIL SPAM DETECTOR
# ============================================================================

class SpamDetector:
    """Real email spam detection"""
    
    def __init__(self):
        self.spam_keywords = [
            'urgent', 'act now', 'limited time', 'click here', 'free money',
            'winner', 'congratulations', 'you have been selected', 'claim now',
            'free gift', 'act fast', 'don\'t miss out', 'special promotion',
            'discount', 'cheap', 'buy now', 'order now', 'subscribe now',
            'unsolicited', 'verify your account', 'suspended', 'compromised',
            'immediate action', 'password expired', 'update your payment'
        ]
        
        self.suspicious_patterns = [
            r'\d{10,}',  # Long number sequences
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Basic email pattern
            r'http[s]?://[^\s]+',  # URLs
            r'\$[0-9,]+',  # Dollar amounts
            r'100%.*free',  # Free promises
            r'guarantee.*money.*back',  # Guarantee claims
            r'credit card', 'bank account', 'social security', 'ssn'
        ]
    
    def analyze_email(self, subject, body, sender):
        """Analyze email for spam indicators"""
        
        result = {
            'is_spam': False,
            'spam_score': 0,
            'max_score': 100,
            'indicators': [],
            'recommendations': []
        }
        
        combined_text = f"{subject} {body} {sender}".lower()
        
        # Check for spam keywords
        for keyword in self.spam_keywords:
            if keyword in combined_text:
                result['indicators'].append({
                    'type': 'keyword',
                    'text': f'Suspicious keyword: "{keyword}"',
                    'severity': 'high' if keyword in ['urgent', 'act now', 'winner'] else 'medium'
                })
                result['spam_score'] += 15
        
        # Check sender
        if sender:
            if self._is_suspicious_sender(sender):
                result['indicators'].append({
                    'type': 'sender',
                    'text': f'Suspicious sender address: {sender}',
                    'severity': 'high'
                })
                result['spam_score'] += 25
        
        # Check for urgency
        urgency_words = ['urgent', 'immediately', '24 hours', '48 hours', 'act now', 'expire']
        urgency_count = sum(1 for word in urgency_words if word in combined_text)
        if urgency_count > 0:
            result['indicators'].append({
                'type': 'urgency',
                'text': f'Urgency tactics detected ({urgency_count} instances)',
                'severity': 'medium'
            })
            result['spam_score'] += urgency_count * 10
        
        # Check for threats
        threat_words = ['suspended', 'blocked', 'compromised', 'terminated', 'legal action']
        if any(word in combined_text for word in threat_words):
            result['indicators'].append({
                'type': 'threat',
                'text': 'Threat or fear tactics detected',
                'severity': 'high'
            })
            result['spam_score'] += 20
        
        # Check for too many exclamation marks
        if combined_text.count('!') > 2:
            result['indicators'].append({
                'type': 'formatting',
                'text': 'Excessive use of exclamation marks',
                'severity': 'low'
            })
            result['spam_score'] += 5
        
        # Check for money-related content
        if re.search(r'\$[\d,]+', combined_text):
            result['indicators'].append({
                'type': 'content',
                'text': 'Contains monetary amounts',
                'severity': 'medium'
            })
            result['spam_score'] += 10
        
        # Check for link mismatches (simplified)
        links = re.findall(r'https?://[^\s]+', body)
        if links:
            result['indicators'].append({
                'type': 'links',
                'text': f'Contains {len(links)} link(s)',
                'severity': 'medium'
            })
            result['spam_score'] += len(links) * 5
        
        # Determine spam status
        result['is_spam'] = result['spam_score'] >= 30
        
        # Generate recommendations
        if result['is_spam']:
            result['recommendations'].append('Do NOT click any links in this email')
            result['recommendations'].append('Do NOT reply or provide any information')
            result['recommendations'].append('Report this email as spam')
        
        if any('sender' in i['type'] for i in result['indicators']):
            result['recommendations'].append('Verify sender by checking the actual email address')
        
        if any('urgency' in i['type'] for i in result['indicators']):
            result['recommendations'].append('Legitimate organizations rarely use extreme urgency')
        
        return result
    
    def _is_suspicious_sender(self, sender):
        """Check if sender looks suspicious"""
        suspicious_patterns = [
            r'^[a-zA-Z0-9._%+-]+@(?!gmail|yahoo|outlook|company)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            r'\d',  # Contains numbers in domain
            r'[a-zA-Z0-9]{20,}',  # Very long username
        ]
        
        sender_lower = sender.lower()
        
        # Known legitimate domains
        safe_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'company.com']
        
        # Check for misspellings of known companies
        company_misspellings = ['amaz0n', 'micros0ft', 'g00gle', 'paypa1', 'app1e', 'faceb00k']
        if any(company in sender_lower for company in company_misspellings):
            return True
        
        # Check if domain is suspiciously long or contains numbers
        if re.search(r'@.*\d{2,}', sender):
            return True
        
        return False


# ============================================================================
# SOCIAL ENGINEERING SCENARIOS
# ============================================================================

class SocialEngineeringSimulator:
    """Real social engineering attack scenarios"""
    
    def __init__(self):
        # Real-world scenarios
        self.scenarios = {
            'phishing_email': [
                {
                    'id': 1,
                    'name': 'CEO Fraud - Wire Transfer',
                    'difficulty': 'expert',
                    'scenario': {
                        'from': 'ceo.johnson@yourcompany-internal.com',
                        'reply_to': 'ceo.johnson.private@gmail.com',
                        'subject': 'URGENT: Confidential Acquisition - Need Your Help',
                        'body': '''Hi,

I need your help with a confidential acquisition we're working on. This is time-sensitive and needs to be processed today.

I've been negotiating with a vendor and we need to make an immediate wire transfer of $85,000 to complete the deal. I can't discuss details over email, but please process this immediately and keep it confidential.

Please send me the wire details once processed. I'll explain everything when I return from my meeting.

Thanks,
Robert Johnson
CEO''',
                        'red_flags': [
                            'Sender email domain differs from company domain',
                            'Reply-to address is personal Gmail',
                            'Urgency and secrecy pressure',
                            'Unusual financial request from CEO',
                            'No phone verification offered'
                        ]
                    }
                },
                {
                    'id': 2,
                    'name': 'IT Support - Account Verification',
                    'difficulty': 'advanced',
                    'scenario': {
                        'from': 'it-support@company-security.net',
                        'subject': 'Action Required: Password Expiry Notification',
                        'body': '''Dear Employee,

Your network password will expire in 24 hours. To maintain access to your account, please update your credentials immediately.

Click the link below to reset your password:
[Password Reset Link]

If you do not update your password, your account will be locked and you will lose access to all company resources.

Best regards,
IT Support Team
Company Name''',
                        'red_flags': [
                            'External domain (not company domain)',
                            'Generic greeting',
                            'Urgency tactic',
                            'Threat of account lockout',
                            'Suspicious domain for IT support'
                        ]
                    }
                },
                {
                    'id': 3,
                    'name': 'Vendor Invoice - Malware Attachment',
                    'difficulty': 'intermediate',
                    'scenario': {
                        'from': 'accounts@vendor-solutions-inc.com',
                        'subject': 'Invoice #INV-2024-8847 - Payment Due',
                        'body': '''Hello,

Please find attached the invoice for services rendered last month. Payment is due within 7 days.

[INVOICE_ATTACHMENT.exe]

If you have any questions about this invoice, please contact our billing department.

Best regards,
Sarah Williams
Accounts Payable
Vendor Solutions Inc.''',
                        'red_flags': [
                            'Executable attachment (.exe)',
                            'Generic greeting',
                            'Unolicited invoice',
                            'External vendor contact'
                        ]
                    }
                }
            ],
            'smishing': [
                {
                    'id': 1,
                    'name': 'Bank Alert - Account Compromised',
                    'difficulty': 'beginner',
                    'message': 'ALERT: Suspicious activity detected on your account. Your card has been temporarily blocked. Verify your identity immediately: http://bank-secure-verify.com/alert',
                    'red_flags': [
                        'Urgency and fear tactics',
                        'Suspicious URL (not official bank domain)',
                        'Request for personal information',
                        'Unknown number sender'
                    ]
                },
                {
                    'id': 2,
                    'name': 'Package Delivery - Failed Delivery',
                    'difficulty': 'beginner',
                    'message': 'USPS: Your package could not be delivered. To reschedule, please confirm your address and payment of $2.99 redelivery fee: http://usps-delivery-verify.com/r/892847',
                    'red_flags': [
                        'Request for payment',
                        'Suspicious URL',
                        'Unknown sender',
                        'Generic tracking number format'
                    ]
                }
            ],
            'vishing': [
                {
                    'id': 1,
                    'name': 'IT Help Desk - Remote Access',
                    'difficulty': 'advanced',
                    'script': [
                        {
                            'speaker': 'attacker',
                            'text': "Hi, this is Mike from IT Support. We're seeing some unusual activity on your computer and need to remotely access it to fix a virus that's spreading through the network."
                        },
                        {
                            'speaker': 'attacker',
                            'text': "I know this is inconvenient, but if we don't act fast, the virus could corrupt all the files on your computer and spread to everyone in the company."
                        },
                        {
                            'speaker': 'attacker',
                            'text': "I just need you to download this remote access tool and give me the code that appears on your screen. It's quick - just a few clicks."
                        },
                        {
                            'speaker': 'attacker',
                            'text': "Also, while we're fixing this, can you confirm your login password so we can verify your identity? It's just a security requirement."
                        }
                    ],
                    'red_flags': [
                        'Unsolicited call from IT',
                        'Urgency and fear tactics',
                        'Request to download software',
                        'Request for password/credentials',
                        'No verification of identity offered',
                        'Claiming to fix something not reported'
                    ]
                },
                {
                    'id': 2,
                    'name': 'Executive Assistant - CEO Request',
                    'difficulty': 'expert',
                    'script': [
                        {
                            'speaker': 'attacker',
                            'text': "Hello, this is Sarah, Mr. Johnson's executive assistant. He's in a meeting right now but needs a favor from you urgently."
                        },
                        {
                            'speaker': 'attacker',
                            'text': "We're closing an important deal and need you to process a wire transfer immediately. He's asked me to walk you through it."
                        },
                        {
                            'speaker': 'attacker',
                            'text': "I know it's unusual, but this is highly confidential and time-sensitive. Can you keep this between us for now?"
                        },
                        {
                            'speaker': 'attacker',
                            'text': "Please don't bother the CFO - Mr. Johnson has already approved this. Just follow my instructions and we'll get this done."
                        }
                    ],
                    'red_flags': [
                        'Unsolicited executive contact',
                        'Pressure to bypass normal procedures',
                        'Confidentiality request',
                        'Request to avoid checking with others',
                        'Urgency to prevent verification',
                        'Unusual financial request'
                    ]
                }
            ],
            'social_media': [
                {
                    'id': 1,
                    'name': 'LinkedIn - Job Offer Scam',
                    'difficulty': 'intermediate',
                    'scenario': {
                        'platform': 'LinkedIn',
                        'message': "Hi! I came across your profile and I'm impressed with your experience. We're hiring for a senior position at a Fortune 500 company. The salary is $150k+ plus benefits. Are you interested? Click here to apply: career-opportunity-verify.com/apply",
                        'red_flags': [
                            'Too good to be true offer',
                            'External suspicious link',
                            'Generic message (no specific details)',
                            'Unknown recruiter',
                            'No company name mentioned initially'
                        ]
                    }
                },
                {
                    'id': 2,
                    'name': 'Facebook - Friend Request',
                    'difficulty': 'beginner',
                    'scenario': {
                        'platform': 'Facebook',
                        'message': "Hi! I'm your colleague from the marketing department. I found you on Facebook and wanted to connect. Also, I found some photos from the company party last week! Here: facebook-photos-share.com/photos",
                        'red_flags': [
                            'Unknown person claiming to be colleague',
                            'Suspicious external link',
                            'Curiosity bait ("found your photos")',
                            'Not verified as real colleague'
                        ]
                    }
                }
            ]
        }
    
    def get_scenario(self, category, difficulty=None):
        """Get a random scenario"""
        scenarios = self.scenarios.get(category, [])
        
        if difficulty:
            scenarios = [s for s in scenarios if s.get('difficulty') == difficulty]
        
        return random.choice(scenarios) if scenarios else None
    
    def get_all_scenarios(self):
        """Get all available scenarios"""
        return self.scenarios


# ============================================================================
# API ROUTES
# ============================================================================

password_analyzer = PasswordAnalyzer()
spam_detector = SpamDetector()
se_simulator = SocialEngineeringSimulator()

@app.route('/api/analyze-password', methods=['POST'])
def analyze_password():
    """Analyze password vulnerability"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = password_analyzer.analyze_password(password)
    return jsonify(result)

@app.route('/api/detect-spam', methods=['POST'])
def detect_spam():
    """Detect if email is spam"""
    data = request.json
    
    result = spam_detector.analyze_email(
        subject=data.get('subject', ''),
        body=data.get('body', ''),
        sender=data.get('sender', '')
    )
    
    return jsonify(result)

@app.route('/api/get-scenario', methods=['GET'])
def get_scenario():
    """Get a social engineering scenario"""
    category = request.args.get('category', 'phishing_email')
    difficulty = request.args.get('difficulty')
    
    scenario = se_simulator.get_scenario(category, difficulty)
    
    if not scenario:
        return jsonify({'error': 'No scenario found'}), 404
    
    return jsonify(scenario)

@app.route('/api/get-all-scenarios', methods=['GET'])
def get_all_scenarios():
    """Get all social engineering scenarios"""
    return jsonify(se_simulator.get_all_scenarios())

# ============================================================================
# SECURITY COMPLIANCE CHECKER
# ============================================================================

class ComplianceChecker:
    """Check password against security compliance standards"""
    
    def __init__(self):
        self.standards = {
            'pci_dss': {
                'name': 'PCI-DSS (Payment Card Industry)',
                'requirements': [
                    {'id': '8.2', 'description': 'Minimum 7 characters', 'check': lambda p: len(p) >= 7},
                    {'id': '8.2', 'description': 'Contains numeric and alphabetic', 'check': lambda p: bool(re.search(r'[a-zA-Z]', p)) and bool(re.search(r'[0-9]', p))},
                    {'id': '8.5', 'description': 'Not same as previous 4 passwords', 'check': lambda p: True}  # Simulated
                ]
            },
            'nist': {
                'name': 'NIST SP 800-63B',
                'requirements': [
                    {'id': '5.1.1', 'description': 'Minimum 8 characters', 'check': lambda p: len(p) >= 8},
                    {'id': '5.1.1', 'description': 'Maximum 64 characters', 'check': lambda p: len(p) <= 64},
                    {'id': '5.1.1', 'description': 'Allow all printable ASCII characters', 'check': lambda p: bool(re.search(r'^[\x20-\x7E]+
            }
            .vulnerable { color: var(--danger); }
            .safe { color: var(--primary); }
            .warning { color: var(--warning); }
            .btn-neon {
                background: linear-gradient(135deg, var(--primary), var(--info));
                border: none;
                color: var(--dark);
                font-weight: bold;
            }
            .btn-neon:hover {
                box-shadow: 0 0 20px var(--primary);
                transform: translateY(-2px);
            }
            .attack-card {
                cursor: pointer;
                transition: all 0.3s;
            }
            .attack-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,255,136,0.2);
            }
            .nav-link {
                color: #fff !important;
            }
            .nav-link.active {
                border-bottom: 2px solid var(--primary) !important;
            }
            .scenario-text {
                white-space: pre-wrap;
                font-family: monospace;
                background: rgba(0,0,0,0.3);
                padding: 15px;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark" style="background: rgba(0,0,0,0.5);">
            <div class="container">
                <a class="navbar-brand neon-text" href="#">
                    <i class="fas fa-shield-alt"></i> CyberShield AI
                </a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav me-auto">
                        <li class="nav-item"><a class="nav-link active" href="#" onclick="showTab('password')">Password Lab</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('spam')">Email Scanner</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('social')">Social Engineering</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('attack')">Attack Sim</a></li>
                    </ul>
                </div>
            </div>
        </nav>

        <div class="container py-4">
            <!-- Password Analyzer -->
            <div id="password-tab" class="tab-content">
                <div class="row">
                    <div class="col-lg-8">
                        <div class="glass-panel p-4 mb-4">
                            <h4 class="mb-3"><i class="fas fa-key"></i> Password Vulnerability Analyzer</h4>
                            <div class="input-group mb-3">
                                <input type="password" class="form-control bg-dark text-light border-secondary" id="passwordInput" placeholder="Enter password to analyze...">
                                <button class="btn btn-neon" onclick="analyzePassword()">
                                    <i class="fas fa-search"></i> Analyze
                                </button>
                            </div>
                            <div id="passwordResults"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="glass-panel p-4">
                            <h5 class="mb-3">Quick Tips</h5>
                            <ul class="list-unstyled">
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Use 12+ characters</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Mix uppercase & lowercase</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Add numbers & symbols</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Avoid common words</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Spam Detector -->
            <div id="spam-tab" class="tab-content" style="display:none;">
                <div class="glass-panel p-4">
                    <h4 class="mb-4"><i class="fas fa-envelope-open-text"></i> Email Spam Detector</h4>
                    <div class="mb-3">
                        <label class="form-label">Sender Email</label>
                        <input type="text" class="form-control bg-dark text-light border-secondary" id="senderInput" placeholder="sender@example.com">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Subject</label>
                        <input type="text" class="form-control bg-dark text-light border-secondary" id="subjectInput" placeholder="Email subject">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email Body</label>
                        <textarea class="form-control bg-dark text-light border-secondary" id="bodyInput" rows="6" placeholder="Email content..."></textarea>
                    </div>
                    <button class="btn btn-neon" onclick="detectSpam()">
                        <i class="fas fa-search"></i> Analyze Email
                    </button>
                    <div id="spamResults" class="mt-4"></div>
                </div>
            </div>

            <!-- Social Engineering -->
            <div id="social-tab" class="tab-content" style="display:none;">
                <div class="row">
                    <div class="col-md-4 mb-4">
                        <div class="glass-panel p-3">
                            <h5 class="mb-3">Scenario Types</h5>
                            <div class="d-grid gap-2">
                                <button class="btn btn-outline-light" onclick="loadScenario('phishing_email')">
                                    <i class="fas fa-envelope"></i> Phishing Email
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('smishing')">
                                    <i class="fas fa-sms"></i> SMS Phishing
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('vishing')">
                                    <i class="fas fa-phone"></i> Voice Phishing
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('social_media')">
                                    <i class="fab fa-social-media"></i> Social Media
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-8">
                        <div class="glass-panel p-4">
                            <h4 id="scenarioTitle" class="mb-3">Select a Scenario Type</h4>
                            <div id="scenarioContent"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attack Simulation -->
            <div id="attack-tab" class="tab-content" style="display:none;">
                <div class="glass-panel p-4">
                    <h4 class="mb-4"><i class="fas fa-bug"></i> Attack Simulation</h4>
                    <div class="mb-3">
                        <label class="form-label">Enter Password to Test</label>
                        <input type="password" class="form-control bg-dark text-light border-secondary" id="attackPassword" placeholder="Password to test...">
                    </div>
                    <div class="row mb-4">
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('brute_force')">
                                <h6><i class="fas fa-lock-open"></i> Brute Force</h6>
                                <small class="text-muted">Tries all combinations</small>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('dictionary')">
                                <h6><i class="fas fa-book"></i> Dictionary</h6>
                                <small class="text-muted">Uses word lists</small>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('rainbow_table')">
                                <h6><i class="fas fa-table"></i> Rainbow Table</h6>
                                <small class="text-muted">Hash lookup</small>
                            </div>
                        </div>
                    </div>
                    <div id="attackResults"></div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            const API_URL = '';
            
            function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
                document.getElementById(tabName + '-tab').style.display = 'block';
                document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
                event.target.classList.add('active');
            }

            async function analyzePassword() {
                const password = document.getElementById('passwordInput').value;
                if (!password) return alert('Please enter a password');
                
                const response = await fetch(API_URL + '/api/analyze-password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password})
                });
                
                const data = await response.json();
                displayPasswordResults(data);
            }

            function displayPasswordResults(data) {
                let html = '<div class="mt-4">';
                html += '<h5 class="mb-3">Analysis Results</h5>';
                
                // Score
                const scoreClass = data.strength_score >= 70 ? 'safe' : (data.strength_score >= 40 ? 'warning' : 'vulnerable');
                html += \`<div class="mb-3">
                    <strong>Strength Score:</strong> 
                    <span class="\${scoreClass}">\${data.strength_score}/100</span>
                </div>\`;
                
                // Vulnerabilities
                if (data.vulnerabilities.length > 0) {
                    html += '<h6 class="mt-3">Vulnerabilities Found:</h6>';
                    data.vulnerabilities.forEach(v => {
                        html += \`<div class="alert alert-\${v.severity === 'critical' ? 'danger' : 'warning'} py-2">
                            <i class="fas fa-exclamation-triangle"></i> \${v.description}
                        </div>\`;
                    });
                }
                
                // Attack Vulnerabilities
                html += '<h6 class="mt-4">Attack Vulnerability Analysis:</h6>';
                html += '<div class="row">';
                for (const [attack, info] of Object.entries(data.attack_vulnerabilities)) {
                    const status = info.vulnerable ? '<span class="badge bg-danger">Vulnerable</span>' : '<span class="badge bg-success">Protected</span>';
                    html += \`<div class="col-md-6 mb-2">
                        <div class="glass-panel p-2">
                            <strong>\${attack.replace('_', ' ').toUpperCase()}</strong> \${status}
                            <br><small>\${info.description}</small>
                        </div>
                    </div>\`;
                }
                html += '</div>';
                
                // Recommendations
                if (data.recommendations.length > 0) {
                    html += '<h6 class="mt-4">Recommendations:</h6>';
                    data.recommendations.forEach(r => {
                        const color = r.priority === 'critical' ? 'danger' : (r.priority === 'success' ? 'success' : 'info');
                        html += \`<div class="alert alert-\${color} py-2">\${r.text}</div>\`;
                    });
                }
                
                html += '</div>';
                document.getElementById('passwordResults').innerHTML = html;
            }

            async function detectSpam() {
                const sender = document.getElementById('senderInput').value;
                const subject = document.getElementById('subjectInput').value;
                const body = document.getElementById('bodyInput').value;
                
                if (!sender || !subject) return alert('Please enter sender and subject');
                
                const response = await fetch(API_URL + '/api/detect-spam', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({sender, subject, body})
                });
                
                const data = await response.json();
                
                let html = '<div class="mt-4">';
                const resultClass = data.is_spam ? 'danger' : 'success';
                const resultText = data.is_spam ? 'SPAM DETECTED' : 'NOT SPAM';
                
                html += \`<div class="alert alert-\${resultClass}">
                    <h5><i class="fas \${data.is_spam ? 'fa-exclamation-circle' : 'fa-check-circle'}"></i> \${resultText}</h5>
                    <p>Spam Score: \${data.spam_score}/100</p>
                </div>\`;
                
                if (data.indicators.length > 0) {
                    html += '<h6>Spam Indicators:</h6>';
                    data.indicators.forEach(i => {
                        html += \`<div class="alert alert-warning py-1 mb-1"><small>\${i.text}</small></div>\`;
                    });
                }
                
                html += '</div>';
                document.getElementById('spamResults').innerHTML = html;
            }

            async function loadScenario(category) {
                const response = await fetch(API_URL + '/api/get-scenario?category=' + category);
                const data = await response.json();
                
                let html = '<h5>' + data.name + '</h5>';
                html += '<p class="text-muted">Difficulty: ' + (data.difficulty || 'N/A') + '</p>';
                
                if (data.scenario) {
                    html += \`<div class="scenario-text">From: \${data.scenario.from}
Subject: \${data.scenario.subject}

\${data.scenario.body}</div>\`;
                } else if (data.message) {
                    html += \`<div class="scenario-text">\${data.message}</div>\`;
                } else if (data.script) {
                    data.script.forEach((line, i) => {
                        html += \`<div class="mb-2"><strong>\${line.speaker === 'attacker' ? '🎭 Scammer' : '👤 You'}:</strong> \${line.text}</div>\`;
                    });
                }
                
                html += '<h6 class="mt-4">Red Flags to Identify:</h6>';
                html += '<ul class="list-group">';
                (data.red_flags || data.scenario?.red_flags || []).forEach(flag => {
                    html += \`<li class="list-group-item bg-dark text-light border-secondary">\${flag}</li>\`;
                });
                html += '</ul>';
                
                document.getElementById('scenarioTitle').textContent = data.name;
                document.getElementById('scenarioContent').innerHTML = html;
            }

            async function runAttack(attackType) {
                const password = document.getElementById('attackPassword').value;
                if (!password) return alert('Please enter a password to test');
                
                const response = await fetch(API_URL + '/api/run-attack-simulation', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({attack_type: attackType, password})
                });
                
                const data = await response.json();
                
                let html = '<div class="mt-4">';
                html += '<h5>Attack Simulation: ' + attackType.replace('_', ' ').toUpperCase() + '</h5>';
                
                data.simulation_steps.forEach(step => {
                    html += \`<div class="py-1"><code>\${step.message}</code></div>\`;
                });
                
                const resultClass = data.vulnerable ? 'danger' : 'success';
                html += \`<div class="alert alert-\${resultClass} mt-3">
                    <strong>\${data.vulnerable ? '⚠️ PASSWORD VULNERABLE!' : '✅ Password Protected!'}</strong>
                    <p>Success Probability: \${(data.success_probability * 100).toFixed(1)}%</p>
                    <small>\${data.protection}</small>
                </div>\`;
                
                html += '</div>';
                document.getElementById('attackResults').innerHTML = html;
            }
        </script>
    </body>
    </html>
    '''
    
if __name__ == '__main__':
    print("=" * 50)
    print("CyberShield AI Security Simulator")
    print("=" * 50)
    print("\nStarting server...")
    print("Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
, p))}
                ]
            },
            'hipaa': {
                'name': 'HIPAA Security Rule',
                'requirements': [
                    {'id': '164.312', 'description': 'Minimum 8 characters', 'check': lambda p: len(p) >= 8},
                    {'id': '164.312', 'description': 'Mix of upper, lower, numbers, special', 'check': lambda p: sum([bool(re.search(r'[a-z]', p)), bool(re.search(r'[A-Z]', p)), bool(re.search(r'[0-9]', p)), bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', p))]) >= 3}
                ]
            },
            'gdpr': {
                'name': 'GDPR Compliance',
                'requirements': [
                    {'id': 'Art.32', 'description': 'Minimum 8 characters', 'check': lambda p: len(p) >= 8},
                    {'id': 'Art.32', 'description': 'Contains at least one letter', 'check': lambda p: bool(re.search(r'[a-zA-Z]', p))},
                    {'id': 'Art.32', 'description': 'Contains at least one number', 'check': lambda p: bool(re.search(r'[0-9]', p))}
                ]
            },
            'iso27001': {
                'name': 'ISO 27001',
                'requirements': [
                    {'id': 'A.9.4', 'description': 'Minimum 8 characters', 'check': lambda p: len(p) >= 8},
                    {'id': 'A.9.4', 'description': 'Mix of character types', 'check': lambda p: sum([bool(re.search(r'[a-z]', p)), bool(re.search(r'[A-Z]', p)), bool(re.search(r'[0-9]', p)), bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', p))]) >= 3}
                ]
            }
        }
        
    def check_password(self, password):
        """Check password against all compliance standards"""
        results = {}
        
        for standard_id, standard in self.standards.items():
            results[standard_id] = {
                'name': standard['name'],
                'compliant': True,
                'requirements': []
            }
            
            for req in standard['requirements']:
                try:
                    passed = req['check'](password)
                    results[standard_id]['requirements'].append({
                        'id': req['id'],
                        'description': req['description'],
                        'passed': passed
                    })
                    if not passed:
                        results[standard_id]['compliant'] = False
                except:
                    results[standard_id]['requirements'].append({
                        'id': req['id'],
                        'description': req['description'],
                        'passed': False
                    })
                    results[standard_id]['compliant'] = False
        
        return results


# ============================================================================
# BREACH CHECKER
# ============================================================================

class BreachChecker:
    """Simulated password breach database checker"""
    
    def __init__(self):
        # Simulated breached password database (in real world, use HaveIBeenPwned API)
        self.breached_passwords = set([
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
            'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
            'qazwsx', 'michael', 'football', 'password1', 'password123', 'welcome',
            'jesus', 'ninja', 'mustang', 'password12', 'admin', 'login', 'starwars',
            'hello', 'charlie', 'donald', 'password2', 'admin123', 'root', 'toor',
            'pass', 'test', 'guest', 'master123', 'changeme', 'secret', '123qwe'
        ])
        
    def check_breach(self, password):
        """Check if password has been in a breach"""
        password_lower = password.lower()
        is_breached = password_lower in self.breached_passwords
        
        result = {
            'breached': is_breached,
            'breach_count': random.randint(10000, 5000000) if is_breached else 0,
            'breach_sources': []
        }
        
        if is_breached:
            result['breach_sources'] = [
                'LinkedIn (2016)',
                'Adobe (2013)',
                'Dropbox (2012)',
                'MySpace (2008)'
            ][:random.randint(1, 3)]
        
        return result


# ============================================================================
# SECURITY SCORECARD GENERATOR
# ============================================================================

class SecurityScorecard:
    """Generate comprehensive security scorecards"""
    
    def __init__(self):
        self.categories = {
            'password': {'weight': 0.35, 'score': 0},
            'email_security': {'weight': 0.25, 'score': 0},
            'social_engineering': {'weight': 0.20, 'score': 0},
            'awareness': {'weight': 0.20, 'score': 0}
        }
        
    def generate_scorecard(self, password_analysis, spam_analysis=None, quiz_results=None):
        """Generate a comprehensive security scorecard"""
        scorecard = {
            'overall_score': 0,
            'grade': 'F',
            'categories': {},
            'recommendations': [],
            'strengths': [],
            'risk_factors': [],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Password score
        if password_analysis:
            pwd_score = password_analysis.get('strength_score', 0)
            self.categories['password']['score'] = pwd_score
            
            if pwd_score >= 80:
                scorecard['strengths'].append('Strong password practices')
            elif pwd_score >= 60:
                scorecard['recommendations'].append('Improve password strength')
            else:
                scorecard['risk_factors'].append('Weak password detected')
        
        # Email security score
        if spam_analysis:
            email_score = max(0, 100 - spam_analysis.get('spam_score', 0))
            self.categories['email_security']['score'] = email_score
            
            if email_score >= 80:
                scorecard['strengths'].append('Good email security awareness')
            else:
                scorecard['risk_factors'].append('Email security needs improvement')
        
        # Social engineering score
        scorecard['categories']['social_engineering'] = {
            'score': random.randint(50, 90),
            'weight': 0.20
        }
        
        # Awareness score
        if quiz_results:
            awareness_score = quiz_results.get('average_score', 0)
        else:
            awareness_score = random.randint(40, 80)
        scorecard['categories']['awareness'] = {
            'score': awareness_score,
            'weight': 0.20
        }
        
        if awareness_score >= 70:
            scorecard['strengths'].append('Good security awareness')
        else:
            scorecard['recommendations'].append('Complete more training modules')
        
        # Calculate overall score
        total_score = 0
        for cat, data in self.categories.items():
            total_score += data['score'] * data['weight']
        
        scorecard['overall_score'] = int(total_score)
        
        # Assign grade
        if total_score >= 90:
            scorecard['grade'] = 'A+'
        elif total_score >= 80:
            scorecard['grade'] = 'A'
        elif total_score >= 70:
            scorecard['grade'] = 'B'
        elif total_score >= 60:
            scorecard['grade'] = 'C'
        elif total_score >= 50:
            scorecard['grade'] = 'D'
        else:
            scorecard['grade'] = 'F'
        
        scorecard['categories'] = self.categories.copy()
        
        # Generate recommendations
        scorecard['recommendations'].extend([
            'Enable multi-factor authentication',
            'Use a password manager',
            'Regular security training'
        ])
        
        return scorecard


# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

class ThreatIntelligence:
    """Threat intelligence and live threat data"""
    
    def __init__(self):
        self.threat_types = [
            {'type': 'Ransomware', 'count': 245, 'trend': 'up', 'risk': 'critical'},
            {'type': 'Phishing', 'count': 1892, 'trend': 'up', 'risk': 'high'},
            {'type': 'Malware', 'count': 567, 'trend': 'down', 'risk': 'high'},
            {'type': 'DDoS', 'count': 123, 'trend': 'stable', 'risk': 'medium'},
            {'type': 'Zero-Day', 'count': 45, 'trend': 'up', 'risk': 'critical'},
            {'type': 'Insider Threat', 'count': 78, 'trend': 'up', 'risk': 'high'},
            {'type': 'APT', 'count': 23, 'trend': 'stable', 'risk': 'critical'},
            {'type': 'Cryptomining', 'count': 156, 'trend': 'down', 'risk': 'low'}
        ]
        
        self.attack_vectors = [
            {'vector': 'Email', 'percentage': 35},
            {'vector': 'Web', 'percentage': 28},
            {'vector': 'Network', 'percentage': 18},
            {'vector': 'USB/Device', 'percentage': 10},
            {'vector': 'Social', 'percentage': 9}
        ]
        
        self.geo_threats = [
            {'country': 'China', 'threats': 12500, 'lat': 35.86, 'lon': 104.19},
            {'country': 'Russia', 'threats': 8900, 'lat': 61.52, 'lon': 105.31},
            {'country': 'USA', 'threats': 7200, 'lat': 37.09, 'lon': -95.71},
            {'country': 'Brazil', 'threats': 4500, 'lat': -14.23, 'lon': -51.92},
            {'country': 'India', 'threats': 3800, 'lat': 20.59, 'lon': 78.96},
            {'country': 'Germany', 'threats': 2100, 'lat': 51.16, 'lon': 10.45}
        ]
        
    def get_threat_data(self):
        """Get current threat intelligence data"""
        return {
            'threat_types': self.threat_types,
            'attack_vectors': self.attack_vectors,
            'geo_threats': self.geo_threats,
            'total_threats': sum(t['count'] for t in self.threat_types),
            'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
        }


# ============================================================================
# SECURITY QUIZ ENGINE
# ============================================================================

class SecurityQuiz:
    """Interactive security quiz with adaptive difficulty"""
    
    def __init__(self):
        self.questions = [
            {
                'id': 1,
                'category': 'password',
                'question': 'What is the minimum recommended password length?',
                'options': ['6 characters', '8 characters', '12 characters', '16 characters'],
                'correct': 2,
                'explanation': 'NIST and most security experts recommend at least 12 characters for strong passwords.'
            },
            {
                'id': 2,
                'category': 'phishing',
                'question': 'Which is a common sign of a phishing email?',
                'options': ['Personal greeting', 'Urgent action required', 'Company logo', 'Correct spelling'],
                'correct': 1,
                'explanation': 'Phishing emails often create urgency to pressure victims into acting without thinking.'
            },
            {
                'id': 3,
                'category': 'social',
                'question': 'What is tailgating in security?',
                'options': ['Following someone into a secure area', 'Sending follow-up emails', 'Online harassment', 'Password guessing'],
                'correct': 0,
                'explanation': 'Tailgating is when an unauthorized person follows an authorized person into a secure area.'
            },
            {
                'id': 4,
                'category': 'password',
                'question': 'Which is the strongest password practice?',
                'options': ['Using your birthday', 'Reusing passwords', 'Using a password manager', 'Writing passwords on paper'],
                'correct': 2,
                'explanation': 'Password managers securely store unique, complex passwords for each account.'
            },
            {
                'id': 5,
                'category': 'email',
                'question': 'What should you do before clicking a link in an email?',
                'options': ['Click immediately', 'Hover over the link to check URL', 'Forward to colleagues', 'Download attachments first'],
                'correct': 1,
                'explanation': 'Hovering over links reveals the actual URL, helping identify malicious destinations.'
            },
            {
                'id': 6,
                'category': 'mfa',
                'question': 'What is the most secure 2FA method?',
                'options': ['SMS text', 'Email code', 'Hardware token', 'Phone call'],
                'correct': 2,
                'explanation': 'Hardware tokens (like YubiKey) are the most secure as they cannot be intercepted.'
            },
            {
                'id': 7,
                'category': 'social',
                'question': 'What is pretexting?',
                'options': ['Writing a preview', 'Creating a false scenario to obtain information', 'Testing software', 'Sending spam'],
                'correct': 1,
                'explanation': 'Pretexting involves creating a fabricated scenario to trick victims into revealing information.'
            },
            {
                'id': 8,
                'category': 'ransomware',
                'question': 'What is the best defense against ransomware?',
                'options': ['Pay the ransom', 'Regular backups', 'Use any browser', 'Disable antivirus'],
                'correct': 1,
                'explanation': 'Regular offline backups ensure you can recover data without paying the ransom.'
            }
        ]
        
    def get_quiz(self, category=None, count=5):
        """Get quiz questions, optionally filtered by category"""
        questions = self.questions.copy()
        
        if category:
            questions = [q for q in questions if q['category'] == category]
        
        random.shuffle(questions)
        return questions[:count]
    
    def check_answer(self, question_id, answer_index):
        """Check if answer is correct"""
        question = next((q for q in self.questions if q['id'] == question_id), None)
        
        if not question:
            return {'correct': False, 'explanation': 'Question not found'}
        
        is_correct = answer_index == question['correct']
        
        return {
            'correct': is_correct,
            'correct_answer': question['options'][question['correct']],
            'explanation': question['explanation']
        }


# ============================================================================
# MFA BYPASS SIMULATOR
# ============================================================================

class MFASimulator:
    """Simulate multi-factor authentication bypass techniques"""
    
    def __init__(self):
        self.scenarios = [
            {
                'id': 1,
                'name': 'SIM Swapping',
                'description': 'Attacker transfers your phone number to their SIM card',
                'steps': [
                    'Attacker gathers personal information about target',
                    'Attacker contacts carrier, impersonates victim',
                    'Social engineer convinces carrier to port number',
                    'Attacker receives SMS 2FA codes',
                    'Account compromised'
                ],
                'defense': 'Use authenticator apps instead of SMS, set up carrier PIN'
            },
            {
                'id': 2,
                'name': 'Man-in-the-Middle',
                'description': 'Attacker intercepts authentication process',
                'steps': [
                    'Victim logs into fake site',
                    'Attacker proxies connection to real site',
                    'Victim enters credentials',
                    'Attacker captures session cookie',
                    'Attacker takes over session'
                ],
                'defense': 'Check URL carefully, use hardware tokens'
            },
            {
                'id': 3,
                'name': 'Push Fatigue',
                'description': 'Bombarding victim with authentication requests',
                'steps': [
                    'Attacker obtains password',
                    'Attacker repeatedly sends MFA requests',
                    'Victim frustrated, approves request',
                    'Attacker gains access',
                    'Account compromised'
                ],
                'defense': 'Deny unexpected requests, use number matching'
            },
            {
                'id': 4,
                'name': 'Cookie Theft',
                'description': 'Stealing persistent login cookies',
                'steps': [
                    'Malware installs on victim device',
                    'Captures session cookies',
                    'Attacker exports cookies',
                    'Attacker imports cookies to their browser',
                ],
                'defense': 'Use secure browsers, clear cookies, enable MFA'
            }
        ]
        
    def get_scenarios(self):
        """Get all MFA bypass scenarios"""
        return self.scenarios
    
    def get_scenario(self, scenario_id):
        """Get specific scenario"""
        return next((s for s in self.scenarios if s['id'] == scenario_id), None)


# ============================================================================
# RANSOMWARE SIMULATOR
# ============================================================================

class RansomwareSimulator:
    """Interactive ransomware attack simulation"""
    
    def __init__(self):
        self.stages = [
            {
                'stage': 1,
                'name': 'Initial Access',
                'description': 'How ransomware gains entry',
                'methods': [
                    'Phishing email with malicious attachment',
                    'Exploit kit vulnerabilities',
                    'Remote Desktop Protocol (RDP) brute force',
                    'Malicious updates',
                    'Infected removable media'
                ]
            },
            {
                'stage': 2,
                'name': 'Execution',
                'description': 'Running the malicious payload',
                'methods': [
                    'Macro-enabled documents',
                    'Script-based execution',
                    'DLL side-loading',
                    'Living-off-the-land binaries'
                ]
            },
            {
                'stage': 3,
                'name': 'Persistence',
                'description': 'Maintaining access',
                'methods': [
                    'Registry Run keys',
                    'Scheduled tasks',
                    'Services',
                    'WMI event subscriptions'
                ]
            },
            {
                'stage': 4,
                'name': 'Discovery',
                'description': 'Finding valuable files',
                'methods': [
                    'Scanning for documents',
                    'Mapping network shares',
                    'Identifying backups',
                    'Targeting databases'
                ]
            },
            {
                'stage': 5,
                'name': 'Exfiltration',
                'description': 'Stealing data before encryption',
                'methods': [
                    'Cloud storage APIs',
                    'FTP/SFTP upload',
                    'DNS tunneling',
                    'WebDAV'
                ]
            },
            {
                'stage': 6,
                'name': 'Encryption',
                'description': 'Encrypting files',
                'methods': [
                    'RSA/AES encryption',
                    'Hybrid encryption scheme',
                    'File extension targeting',
                    'Network propagation'
                ]
            },
            {
                'stage': 7,
                'name': 'Extortion',
                'description': 'Demanding payment',
                'methods': [
                    'Ransom note display',
                    'Countdown timers',
                    'Data leak threats',
                    'Dark web publishing'
                ]
            }
        ]
        
    def get_stages(self):
        """Get all ransomware attack stages"""
        return self.stages
    
    def simulate_attack(self, attack_vector):
        """Simulate a ransomware attack"""
        timeline = []
        start_time = time.time()
        
        for stage in self.stages:
            timeline.append({
                'stage': stage['stage'],
                'name': stage['name'],
                'description': stage['description'],
                'timestamp': time.strftime('%H:%M:%S'),
                'completed': True
            })
        
        return {
            'attack_vector': attack_vector,
            'timeline': timeline,
            'total_time': f'{random.randint(2, 8)} hours',
            'files_encrypted': f'{random.randint(10000, 500000)}',
            'data_stolen': f'{random.randint(100, 500)} GB',
            'ransom_demand': f'${random.randint(50000, 500000)}'
        }


# Initialize instances
compliance_checker = ComplianceChecker()
breach_checker = BreachChecker()
security_scorecard = SecurityScorecard()
threat_intelligence = ThreatIntelligence()
security_quiz = SecurityQuiz()
mfa_simulator = MFASimulator()
ransomware_simulator = RansomwareSimulator()

@app.route('/api/check-compliance', methods=['POST'])
def check_compliance():
    """Check password compliance against standards"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = compliance_checker.check_password(password)
    return jsonify(result)

@app.route('/api/check-breach', methods=['POST'])
def check_breach():
    """Check if password has been breached"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    
    result = breach_checker.check_breach(password)
    return jsonify(result)

@app.route('/api/generate-scorecard', methods=['POST'])
def generate_scorecard():
    """Generate security scorecard"""
    data = request.json
    password_analysis = data.get('password_analysis')
    spam_analysis = data.get('spam_analysis')
    quiz_results = data.get('quiz_results')
    
    result = security_scorecard.generate_scorecard(password_analysis, spam_analysis, quiz_results)
    return jsonify(result)

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """Get threat intelligence data"""
    return jsonify(threat_intelligence.get_threat_data())

@app.route('/api/security-quiz', methods=['GET'])
def get_security_quiz():
    """Get security quiz questions"""
    category = request.args.get('category')
    count = int(request.args.get('count', 5))
    
    questions = security_quiz.get_quiz(category, count)
    return jsonify(questions)

@app.route('/api/check-quiz-answer', methods=['POST'])
def check_quiz_answer():
    """Check quiz answer"""
    data = request.json
    question_id = data.get('question_id')
    answer_index = data.get('answer_index')
    
    result = security_quiz.check_answer(question_id, answer_index)
    return jsonify(result)

@app.route('/api/mfa-scenarios', methods=['GET'])
def get_mfa_scenarios():
    """Get MFA bypass scenarios"""
    return jsonify(mfa_simulator.get_scenarios())

@app.route('/api/mfa-scenario/<int:scenario_id>', methods=['GET'])
def get_mfa_scenario(scenario_id):
    """Get specific MFA bypass scenario"""
    scenario = mfa_simulator.get_scenario(scenario_id)
    if scenario:
        return jsonify(scenario)
    return jsonify({'error': 'Scenario not found'}), 404

@app.route('/api/ransomware-stages', methods=['GET'])
def get_ransomware_stages():
    """Get ransomware attack stages"""
    return jsonify(ransomware_simulator.get_stages())

@app.route('/api/simulate-ransomware', methods=['POST'])
def simulate_ransomware():
    """Simulate ransomware attack"""
    data = request.json
    attack_vector = data.get('attack_vector', 'phishing')
    
    result = ransomware_simulator.simulate_attack(attack_vector)
    return jsonify(result)

@app.route('/')
def index():
    """Serve the frontend"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CyberShield AI - Security Simulator</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            :root {
                --primary: #00ff88;
                --danger: #ff3366;
                --warning: #ffaa00;
                --info: #00d4ff;
                --dark: #0a0e17;
                --darker: #050810;
            }
            body {
                background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
                min-height: 100vh;
                color: #fff;
            }
            .glass-panel {
                background: rgba(255,255,255,0.05);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 16px;
            }
            .neon-text {
                text-shadow: 0 0 10px var(--primary);
            }
            .vulnerable { color: var(--danger); }
            .safe { color: var(--primary); }
            .warning { color: var(--warning); }
            .btn-neon {
                background: linear-gradient(135deg, var(--primary), var(--info));
                border: none;
                color: var(--dark);
                font-weight: bold;
            }
            .btn-neon:hover {
                box-shadow: 0 0 20px var(--primary);
                transform: translateY(-2px);
            }
            .attack-card {
                cursor: pointer;
                transition: all 0.3s;
            }
            .attack-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,255,136,0.2);
            }
            .nav-link {
                color: #fff !important;
            }
            .nav-link.active {
                border-bottom: 2px solid var(--primary) !important;
            }
            .scenario-text {
                white-space: pre-wrap;
                font-family: monospace;
                background: rgba(0,0,0,0.3);
                padding: 15px;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark" style="background: rgba(0,0,0,0.5);">
            <div class="container">
                <a class="navbar-brand neon-text" href="#">
                    <i class="fas fa-shield-alt"></i> CyberShield AI
                </a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav me-auto">
                        <li class="nav-item"><a class="nav-link active" href="#" onclick="showTab('password')">Password Lab</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('spam')">Email Scanner</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('social')">Social Engineering</a></li>
                        <li class="nav-item"><a class="nav-link" href="#" onclick="showTab('attack')">Attack Sim</a></li>
                    </ul>
                </div>
            </div>
        </nav>

        <div class="container py-4">
            <!-- Password Analyzer -->
            <div id="password-tab" class="tab-content">
                <div class="row">
                    <div class="col-lg-8">
                        <div class="glass-panel p-4 mb-4">
                            <h4 class="mb-3"><i class="fas fa-key"></i> Password Vulnerability Analyzer</h4>
                            <div class="input-group mb-3">
                                <input type="password" class="form-control bg-dark text-light border-secondary" id="passwordInput" placeholder="Enter password to analyze...">
                                <button class="btn btn-neon" onclick="analyzePassword()">
                                    <i class="fas fa-search"></i> Analyze
                                </button>
                            </div>
                            <div id="passwordResults"></div>
                        </div>
                    </div>
                    <div class="col-lg-4">
                        <div class="glass-panel p-4">
                            <h5 class="mb-3">Quick Tips</h5>
                            <ul class="list-unstyled">
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Use 12+ characters</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Mix uppercase & lowercase</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Add numbers & symbols</li>
                                <li class="mb-2"><i class="fas fa-check text-success"></i> Avoid common words</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Spam Detector -->
            <div id="spam-tab" class="tab-content" style="display:none;">
                <div class="glass-panel p-4">
                    <h4 class="mb-4"><i class="fas fa-envelope-open-text"></i> Email Spam Detector</h4>
                    <div class="mb-3">
                        <label class="form-label">Sender Email</label>
                        <input type="text" class="form-control bg-dark text-light border-secondary" id="senderInput" placeholder="sender@example.com">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Subject</label>
                        <input type="text" class="form-control bg-dark text-light border-secondary" id="subjectInput" placeholder="Email subject">
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Email Body</label>
                        <textarea class="form-control bg-dark text-light border-secondary" id="bodyInput" rows="6" placeholder="Email content..."></textarea>
                    </div>
                    <button class="btn btn-neon" onclick="detectSpam()">
                        <i class="fas fa-search"></i> Analyze Email
                    </button>
                    <div id="spamResults" class="mt-4"></div>
                </div>
            </div>

            <!-- Social Engineering -->
            <div id="social-tab" class="tab-content" style="display:none;">
                <div class="row">
                    <div class="col-md-4 mb-4">
                        <div class="glass-panel p-3">
                            <h5 class="mb-3">Scenario Types</h5>
                            <div class="d-grid gap-2">
                                <button class="btn btn-outline-light" onclick="loadScenario('phishing_email')">
                                    <i class="fas fa-envelope"></i> Phishing Email
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('smishing')">
                                    <i class="fas fa-sms"></i> SMS Phishing
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('vishing')">
                                    <i class="fas fa-phone"></i> Voice Phishing
                                </button>
                                <button class="btn btn-outline-light" onclick="loadScenario('social_media')">
                                    <i class="fab fa-social-media"></i> Social Media
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-8">
                        <div class="glass-panel p-4">
                            <h4 id="scenarioTitle" class="mb-3">Select a Scenario Type</h4>
                            <div id="scenarioContent"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attack Simulation -->
            <div id="attack-tab" class="tab-content" style="display:none;">
                <div class="glass-panel p-4">
                    <h4 class="mb-4"><i class="fas fa-bug"></i> Attack Simulation</h4>
                    <div class="mb-3">
                        <label class="form-label">Enter Password to Test</label>
                        <input type="password" class="form-control bg-dark text-light border-secondary" id="attackPassword" placeholder="Password to test...">
                    </div>
                    <div class="row mb-4">
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('brute_force')">
                                <h6><i class="fas fa-lock-open"></i> Brute Force</h6>
                                <small class="text-muted">Tries all combinations</small>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('dictionary')">
                                <h6><i class="fas fa-book"></i> Dictionary</h6>
                                <small class="text-muted">Uses word lists</small>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="glass-panel p-3 attack-card" onclick="runAttack('rainbow_table')">
                                <h6><i class="fas fa-table"></i> Rainbow Table</h6>
                                <small class="text-muted">Hash lookup</small>
                            </div>
                        </div>
                    </div>
                    <div id="attackResults"></div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            const API_URL = '';
            
            function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
                document.getElementById(tabName + '-tab').style.display = 'block';
                document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
                event.target.classList.add('active');
            }

            async function analyzePassword() {
                const password = document.getElementById('passwordInput').value;
                if (!password) return alert('Please enter a password');
                
                const response = await fetch(API_URL + '/api/analyze-password', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password})
                });
                
                const data = await response.json();
                displayPasswordResults(data);
            }

            function displayPasswordResults(data) {
                let html = '<div class="mt-4">';
                html += '<h5 class="mb-3">Analysis Results</h5>';
                
                // Score
                const scoreClass = data.strength_score >= 70 ? 'safe' : (data.strength_score >= 40 ? 'warning' : 'vulnerable');
                html += \`<div class="mb-3">
                    <strong>Strength Score:</strong> 
                    <span class="\${scoreClass}">\${data.strength_score}/100</span>
                </div>\`;
                
                // Vulnerabilities
                if (data.vulnerabilities.length > 0) {
                    html += '<h6 class="mt-3">Vulnerabilities Found:</h6>';
                    data.vulnerabilities.forEach(v => {
                        html += \`<div class="alert alert-\${v.severity === 'critical' ? 'danger' : 'warning'} py-2">
                            <i class="fas fa-exclamation-triangle"></i> \${v.description}
                        </div>\`;
                    });
                }
                
                // Attack Vulnerabilities
                html += '<h6 class="mt-4">Attack Vulnerability Analysis:</h6>';
                html += '<div class="row">';
                for (const [attack, info] of Object.entries(data.attack_vulnerabilities)) {
                    const status = info.vulnerable ? '<span class="badge bg-danger">Vulnerable</span>' : '<span class="badge bg-success">Protected</span>';
                    html += \`<div class="col-md-6 mb-2">
                        <div class="glass-panel p-2">
                            <strong>\${attack.replace('_', ' ').toUpperCase()}</strong> \${status}
                            <br><small>\${info.description}</small>
                        </div>
                    </div>\`;
                }
                html += '</div>';
                
                // Recommendations
                if (data.recommendations.length > 0) {
                    html += '<h6 class="mt-4">Recommendations:</h6>';
                    data.recommendations.forEach(r => {
                        const color = r.priority === 'critical' ? 'danger' : (r.priority === 'success' ? 'success' : 'info');
                        html += \`<div class="alert alert-\${color} py-2">\${r.text}</div>\`;
                    });
                }
                
                html += '</div>';
                document.getElementById('passwordResults').innerHTML = html;
            }

            async function detectSpam() {
                const sender = document.getElementById('senderInput').value;
                const subject = document.getElementById('subjectInput').value;
                const body = document.getElementById('bodyInput').value;
                
                if (!sender || !subject) return alert('Please enter sender and subject');
                
                const response = await fetch(API_URL + '/api/detect-spam', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({sender, subject, body})
                });
                
                const data = await response.json();
                
                let html = '<div class="mt-4">';
                const resultClass = data.is_spam ? 'danger' : 'success';
                const resultText = data.is_spam ? 'SPAM DETECTED' : 'NOT SPAM';
                
                html += \`<div class="alert alert-\${resultClass}">
                    <h5><i class="fas \${data.is_spam ? 'fa-exclamation-circle' : 'fa-check-circle'}"></i> \${resultText}</h5>
                    <p>Spam Score: \${data.spam_score}/100</p>
                </div>\`;
                
                if (data.indicators.length > 0) {
                    html += '<h6>Spam Indicators:</h6>';
                    data.indicators.forEach(i => {
                        html += \`<div class="alert alert-warning py-1 mb-1"><small>\${i.text}</small></div>\`;
                    });
                }
                
                html += '</div>';
                document.getElementById('spamResults').innerHTML = html;
            }

            async function loadScenario(category) {
                const response = await fetch(API_URL + '/api/get-scenario?category=' + category);
                const data = await response.json();
                
                let html = '<h5>' + data.name + '</h5>';
                html += '<p class="text-muted">Difficulty: ' + (data.difficulty || 'N/A') + '</p>';
                
                if (data.scenario) {
                    html += \`<div class="scenario-text">From: \${data.scenario.from}
Subject: \${data.scenario.subject}

\${data.scenario.body}</div>\`;
                } else if (data.message) {
                    html += \`<div class="scenario-text">\${data.message}</div>\`;
                } else if (data.script) {
                    data.script.forEach((line, i) => {
                        html += \`<div class="mb-2"><strong>\${line.speaker === 'attacker' ? '🎭 Scammer' : '👤 You'}:</strong> \${line.text}</div>\`;
                    });
                }
                
                html += '<h6 class="mt-4">Red Flags to Identify:</h6>';
                html += '<ul class="list-group">';
                (data.red_flags || data.scenario?.red_flags || []).forEach(flag => {
                    html += \`<li class="list-group-item bg-dark text-light border-secondary">\${flag}</li>\`;
                });
                html += '</ul>';
                
                document.getElementById('scenarioTitle').textContent = data.name;
                document.getElementById('scenarioContent').innerHTML = html;
            }

            async function runAttack(attackType) {
                const password = document.getElementById('attackPassword').value;
                if (!password) return alert('Please enter a password to test');
                
                const response = await fetch(API_URL + '/api/run-attack-simulation', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({attack_type: attackType, password})
                });
                
                const data = await response.json();
                
                let html = '<div class="mt-4">';
                html += '<h5>Attack Simulation: ' + attackType.replace('_', ' ').toUpperCase() + '</h5>';
                
                data.simulation_steps.forEach(step => {
                    html += \`<div class="py-1"><code>\${step.message}</code></div>\`;
                });
                
                const resultClass = data.vulnerable ? 'danger' : 'success';
                html += \`<div class="alert alert-\${resultClass} mt-3">
                    <strong>\${data.vulnerable ? '⚠️ PASSWORD VULNERABLE!' : '✅ Password Protected!'}</strong>
                    <p>Success Probability: \${(data.success_probability * 100).toFixed(1)}%</p>
                    <small>\${data.protection}</small>
                </div>\`;
                
                html += '</div>';
                document.getElementById('attackResults').innerHTML = html;
            }
        </script>
    </body>
    </html>
    '''
    
if __name__ == '__main__':
    print("=" * 50)
    print("CyberShield AI Security Simulator")
    print("=" * 50)
    print("\nStarting server...")
    print("Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
