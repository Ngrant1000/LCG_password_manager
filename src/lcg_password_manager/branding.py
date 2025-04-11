"""
LCG Password Manager Branding Module

This module handles the application's visual identity, including logos,
colors, and styling information.
"""

import os
from pathlib import Path
from PySide6.QtGui import QPixmap, QIcon, QColor
from PySide6.QtCore import Qt
import json
import gettext
from typing import Dict, Optional

# Brand Colors
BRAND_COLORS = {
    'primary': '#245A8E',    # LCG Blue
    'secondary': '#636365',  # LCG Gray
    'accent': '#909090',     # LCG Light Gray
    'background': '#FFFFFF', # White
    'text': '#333333',       # Dark Gray
    'error': '#FF4444',      # Error Red
    'success': '#44FF44',    # Success Green
    'warning': '#FFFF44'     # Warning Yellow
}

# Brand Fonts
BRAND_FONTS = {
    'heading': 'Segoe UI',
    'body': 'Segoe UI',
    'monospace': 'Consolas'
}

# Brand Styles
BRAND_STYLES = {
    'border_radius': '4px',
    'padding': '8px',
    'margin': '4px',
    'shadow': '0 2px 4px rgba(0, 0, 0, 0.1)'
}

class ThemeManager:
    """Manages application themes."""
    
    def __init__(self):
        self._current_theme = "light"
        self._themes = {
            "light": {
                "background": "#FFFFFF",
                "text": "#333333",
                "primary": "#245A8E",
                "secondary": "#636365",
                "accent": "#909090"
            },
            "dark": {
                "background": "#2D2D30",
                "text": "#FFFFFF",
                "primary": "#3478BE",
                "secondary": "#909090",
                "accent": "#636365"
            }
        }
    
    @property
    def current_theme(self) -> str:
        """Get current theme name."""
        return self._current_theme
    
    @current_theme.setter
    def current_theme(self, theme_name: str) -> None:
        """Set current theme."""
        if theme_name not in self._themes:
            raise ValueError(f"Unknown theme: {theme_name}")
        self._current_theme = theme_name
    
    def get_theme_colors(self) -> Dict[str, str]:
        """Get current theme colors."""
        return self._themes[self._current_theme]
    
    def add_custom_theme(self, name: str, colors: Dict[str, str]) -> None:
        """Add a custom theme."""
        required_colors = {"background", "text", "primary", "secondary", "accent"}
        if not all(color in colors for color in required_colors):
            raise ValueError("Theme must define all required colors")
        self._themes[name] = colors
    
    def get_stylesheet(self) -> str:
        """Get stylesheet for current theme."""
        colors = self.get_theme_colors()
        if self._current_theme == "light":
            return f"""
                QMainWindow, QDialog, QWidget {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                }}
                QPushButton {{
                    background-color: {colors['primary']};
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                }}
                QPushButton:hover {{
                    background-color: {colors['secondary']};
                }}
                QLineEdit, QTextEdit, QComboBox, QSpinBox {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                    border: 1px solid {colors['accent']};
                    padding: 4px;
                }}
                QTableView, QTableWidget {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                    gridline-color: {colors['accent']};
                }}
                QTableView::item:selected, QTableWidget::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QHeaderView::section {{
                    background-color: {colors['primary']};
                    color: white;
                    padding: 4px;
                }}
                QMenuBar {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                }}
                QMenuBar::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QMenu {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                }}
                QMenu::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QToolBar {{
                    background-color: {colors['background']};
                    border-bottom: 1px solid {colors['accent']};
                }}
                QStatusBar {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                }}
                QLabel {{
                    color: {colors['text']};
                }}
                QGroupBox {{
                    border: 1px solid {colors['accent']};
                    margin-top: 1ex;
                    color: {colors['text']};
                }}
                QGroupBox::title {{
                    color: {colors['text']};
                }}
            """
        else:  # Dark theme
            return f"""
                QMainWindow, QDialog, QWidget {{
                    background-color: {colors['background']};
                    color: {colors['text']};
                }}
                QPushButton {{
                    background-color: {colors['primary']};
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                }}
                QPushButton:hover {{
                    background-color: #4A8AC3;
                }}
                QLineEdit, QTextEdit, QComboBox, QSpinBox {{
                    background-color: #3E3E42;
                    color: {colors['text']};
                    border: 1px solid #545454;
                    padding: 4px;
                }}
                QTableView, QTableWidget {{
                    background-color: #3E3E42;
                    color: {colors['text']};
                    gridline-color: #545454;
                    alternate-background-color: #383838;
                }}
                QTableView::item:selected, QTableWidget::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QHeaderView::section {{
                    background-color: {colors['primary']};
                    color: white;
                    padding: 4px;
                }}
                QMenuBar {{
                    background-color: #1E1E1E;
                    color: {colors['text']};
                }}
                QMenuBar::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QMenu {{
                    background-color: #2D2D30;
                    color: {colors['text']};
                    border: 1px solid #545454;
                }}
                QMenu::item:selected {{
                    background-color: {colors['primary']};
                    color: white;
                }}
                QToolBar {{
                    background-color: #1E1E1E;
                    border-bottom: 1px solid #545454;
                }}
                QStatusBar {{
                    background-color: #1E1E1E;
                    color: {colors['text']};
                }}
                QLabel {{
                    color: {colors['text']};
                }}
                QGroupBox {{
                    border: 1px solid #545454;
                    margin-top: 1ex;
                    color: {colors['text']};
                }}
                QGroupBox::title {{
                    color: {colors['text']};
                }}
                QTextBrowser {{
                    background-color: #3E3E42;
                    color: {colors['text']};
                    border: 1px solid #545454;
                }}
            """

class LocalizationManager:
    """Manages application localization."""
    
    def __init__(self):
        self._current_locale = "en"
        self._translations = {}
        self._load_translations()
    
    def _load_translations(self) -> None:
        """Load translation files."""
        locale_dir = Path(__file__).parent / 'locales'
        if not locale_dir.exists():
            return
        
        for locale_file in locale_dir.glob('*.json'):
            locale = locale_file.stem
            try:
                with open(locale_file, 'r', encoding='utf-8') as f:
                    self._translations[locale] = json.load(f)
            except Exception as e:
                print(f"Error loading translation {locale}: {e}")
    
    @property
    def current_locale(self) -> str:
        """Get current locale."""
        return self._current_locale
    
    @current_locale.setter
    def current_locale(self, locale: str) -> None:
        """Set current locale."""
        if locale not in self._translations and locale != "en":
            raise ValueError(f"Unsupported locale: {locale}")
        self._current_locale = locale
    
    def get_text(self, key: str, default: Optional[str] = None) -> str:
        """Get translated text for a key."""
        if self._current_locale == "en":
            return default or key
        
        translation = self._translations.get(self._current_locale, {})
        return translation.get(key, default or key)
    
    def get_available_locales(self) -> list:
        """Get list of available locales."""
        return ["en"] + list(self._translations.keys())

class Branding:
    """Handles application branding and styling."""
    
    def __init__(self):
        self._logo_path = Path(__file__).parent / 'assets' / 'lcg-logo-colored.svg'
        self._icon_path = Path(__file__).parent / 'assets' / 'lcg-icon.ico'
        self.theme_manager = ThemeManager()
        self.localization_manager = LocalizationManager()
        
    @property
    def logo(self) -> QPixmap:
        """Returns the LCG logo as a QPixmap."""
        if not self._logo_path.exists():
            return QPixmap()
        return QPixmap(str(self._logo_path))
    
    @property
    def icon(self) -> QIcon:
        """Returns the application icon."""
        if not self._icon_path.exists():
            return QIcon()
        return QIcon(str(self._icon_path))
    
    @property
    def colors(self) -> dict:
        """Returns the brand color palette."""
        return BRAND_COLORS
    
    @property
    def fonts(self) -> dict:
        """Returns the brand font definitions."""
        return BRAND_FONTS
    
    @property
    def styles(self) -> dict:
        """Returns the brand style definitions."""
        return BRAND_STYLES
    
    def get_stylesheet(self) -> str:
        """Returns the application stylesheet with brand colors and styles."""
        # Delegate to the theme manager's stylesheet
        return self.theme_manager.get_stylesheet()
    
    def get_footer_text(self) -> str:
        """Returns the footer text with copyright information."""
        return "© 2023 LCG Password Manager. All rights reserved."
    
    def get_window_title(self) -> str:
        """Returns the window title with branding."""
        return "LCG Password Manager - Secure Enterprise Password Management" 