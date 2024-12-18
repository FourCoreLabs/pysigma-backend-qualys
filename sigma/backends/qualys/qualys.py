from typing import Union, ClassVar, Optional, Tuple, List, Dict, Any
from sigma.conversion.state import ConversionState
from sigma.types import SigmaString, SigmaNumber, SpecialChars
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND
from sigma.types import SigmaCompareExpression

class QualysBackend(TextQueryBackend):
    """Qualys Query Backend."""
    name: ClassVar[str] = "Qualys Query Language Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Qualys Query Language search strings",
    }
    requires_pipeline: ClassVar[bool] = False

    # Operator precedence
    group_expression: ClassVar[str] = "({expr})"
    precedence: ClassVar[Tuple[Any, ...]] = (
        ConditionOR,
        ConditionAND,
    )
    parenthesize: bool = True

    # Basic operators
    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = ":"

    # String output
    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    
    # Value matching expressions
    contains_expression: ClassVar[str] = "{field}:\"{value}\""
    startswith_expression: ClassVar[str] = "{field}:\"{value}\""
    endswith_expression: ClassVar[str] = "{field}:\"{value}\""

    def convert_value_str(self, val: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a Qualys query string."""
        if val.contains_special():
            result = ""
            for c in val.s:
                if isinstance(c, SpecialChars):
                    if c == SpecialChars.WILDCARD_MULTI:
                        result += "*"
                else:
                    result += c
            return result
        return str(val)

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field equals string value expressions."""
        try:
            field = cond.field
            val = self.convert_value_str(cond.value, state)

            # Handle modifiers
            if cond.value.contains_special():
                if "|contains|" in str(cond):
                    return f'{field}:"*{val}*"'
                elif "|endswith|" in str(cond):
                    return f'{field}:"*{val}"'
                elif "|startswith|" in str(cond):
                    return f'{field}:"{val}*"'
                else:
                    return f'{field}:"{val}"'
            return f'{field}:"{val}"'
        except Exception as e:
            raise ValueError(f"Error converting condition: {str(e)}")

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            expressions = []
            for arg in cond.args:
                expr = self.convert_condition(arg, state)
                if expr is not None:
                    expressions.append(expr)
            if not expressions:
                return None
            or_expr = f" {self.or_token} ".join(expressions)
            return self.group_expression.format(expr=or_expr)
        except Exception as e:
            raise ValueError(f"Error converting OR condition: {str(e)}")

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            expressions = []
            for arg in cond.args:
                expr = self.convert_condition(arg, state)
                if expr is not None:
                    expressions.append(expr)
            if not expressions:
                return None
            and_expr = f" {self.and_token} ".join(expressions)
            return self.group_expression.format(expr=and_expr)
        except Exception as e:
            raise ValueError(f"Error converting AND condition: {str(e)}")