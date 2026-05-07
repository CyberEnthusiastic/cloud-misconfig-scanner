"""Rule packs for cloud baseline validation."""
from .aws_rules import AWS_RULES
from .azure_rules import AZURE_RULES

ALL_RULES = AWS_RULES + AZURE_RULES
