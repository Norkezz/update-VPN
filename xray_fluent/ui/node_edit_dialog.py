from __future__ import annotations

from PyQt6.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout
from qfluentwidgets import (
    BodyLabel,
    EditableComboBox,
    LineEdit,
    PrimaryPushButton,
    PushButton,
    SubtitleLabel,
    isDarkTheme,
)


class NodeEditDialog(QDialog):
    def __init__(self, node, existing_groups: list[str], parent=None):
        super().__init__(parent)
        self._node = node
        self.setWindowTitle("Редактировать сервер")
        self.setModal(True)
        self.setMinimumWidth(440)
        bg = "#2b2b2b" if isDarkTheme() else "#f3f3f3"
        self.setStyleSheet(f"NodeEditDialog {{ background-color: {bg}; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(10)

        root.addWidget(SubtitleLabel("Редактировать сервер", self))

        root.addWidget(BodyLabel("Название", self))
        self.name_edit = LineEdit(self)
        self.name_edit.setText(node.name)
        root.addWidget(self.name_edit)

        root.addWidget(BodyLabel("Группа", self))
        self.group_combo = EditableComboBox(self)
        for g in existing_groups:
            self.group_combo.addItem(g)
        self.group_combo.setText(node.group or "")
        root.addWidget(self.group_combo)

        root.addWidget(BodyLabel("Теги (через запятую)", self))
        self.tags_edit = LineEdit(self)
        self.tags_edit.setPlaceholderText("тег1, тег2")
        self.tags_edit.setText(", ".join(node.tags) if node.tags else "")
        root.addWidget(self.tags_edit)

        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = PushButton("Отмена", self)
        self.apply_btn = PrimaryPushButton("Сохранить", self)
        row.addWidget(self.cancel_btn)
        row.addWidget(self.apply_btn)
        root.addLayout(row)

        self.cancel_btn.clicked.connect(self.reject)
        self.apply_btn.clicked.connect(self.accept)

    def get_updated_fields(self) -> dict:
        name = self.name_edit.text().strip()
        group = self.group_combo.text().strip()
        raw_tags = self.tags_edit.text().strip()
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
        return {
            "name": name,
            "group": group,
            "tags": tags,
        }