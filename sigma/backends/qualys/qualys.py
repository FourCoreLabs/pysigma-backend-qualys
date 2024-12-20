import re
from typing import Union, ClassVar, Optional, Tuple, List, Dict, Any, Pattern, Type
from sigma.conversion.state import ConversionState
from sigma.types import SigmaString, SigmaNumber, SpecialChars, SigmaRegularExpression
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import (
    ConditionFieldEqualsValueExpression, 
    ConditionOR, 
    ConditionAND, 
    ConditionNOT,
    ConditionItem
)
from sigma.types import SigmaCompareExpression

class QualysBackend(TextQueryBackend):
    """Qualys Query Backend with full functionality."""
    name: ClassVar[str] = "Qualys Query Language Backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Qualys Query Language search strings",
    }
    requires_pipeline: ClassVar[bool] = False

    # Operator precedence
    group_expression: ClassVar[str] = "({expr})"
    precedence: ClassVar[Tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
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
    add_escaped: ClassVar[str] = "\\"
    filter_chars: ClassVar[str] = ""
    
    # Field quoting and escaping
    field_quote: ClassVar[str] = "'"
    field_quote_pattern: ClassVar[Pattern] = re.compile("^\\w+$")
    field_quote_pattern_negation: ClassVar[bool] = True
    field_escape: ClassVar[str] = "\\"
    field_escape_quote: ClassVar[bool] = True
    field_escape_pattern: ClassVar[Pattern] = re.compile("\\s")

    # Value matching expressions - Fixed formatting
    contains_expression: ClassVar[str] = "{field}:*{value}*"
    startswith_expression: ClassVar[str] = "{field}:{value}*"
    endswith_expression: ClassVar[str] = "{field}:*{value}"
    
    # Regular expressions
    re_expression: ClassVar[str] = '{field} matches regex "{regex}"'
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str, ...]] = ()
    re_escape_escape_char: bool = True

    # Null/None expressions
    field_null_expression: ClassVar[str] = "isnull({field})"

    # Numeric comparison
    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # List operations
    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = True
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "in"
    and_in_operator: ClassVar[str] = "has_all"
    list_separator: ClassVar[str] = ", "

    def convert_value_str(self, val: Union[SigmaString, SigmaNumber], state: ConversionState) -> str:
        """Convert a value into a Qualys query string."""
        if isinstance(val, SigmaNumber):
            return str(val)
            
        if isinstance(val, SigmaString) and val.contains_special():
            result = ""
            for c in val.s:
                if isinstance(c, SpecialChars):
                    if c == SpecialChars.WILDCARD_MULTI:
                        result += self.wildcard_multi
                    elif c == SpecialChars.WILDCARD_SINGLE:
                        result += self.wildcard_single
                else:
                    result += c
            return result
        return str(val)

    def escape_and_quote_field(self, field: str) -> str:
        """Escape and quote field names if necessary."""
        escaped = field
        if self.field_escape:
            escaped = re.sub(
                self.field_escape_pattern,
                lambda m: self.field_escape + m.group(),
                escaped
            )
        if self.field_quote:
            if self.field_quote_pattern:
                if self.field_quote_pattern_negation != bool(self.field_quote_pattern.match(escaped)):
                    escaped = self.field_quote + escaped + self.field_quote
        return escaped

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field equals string value expressions."""
        try:
            field = self.escape_and_quote_field(cond.field)
            val = self.convert_value_str(cond.value, state)

            # Handle special modifiers and wildcards
            if isinstance(cond.value, SigmaString) and cond.value.contains_special():
                if "|contains|" in str(cond):
                    return self.contains_expression.format(field=field, value=val.strip("*"))
                elif "|endswith|" in str(cond):
                    return self.endswith_expression.format(field=field, value=val.strip("*"))
                elif "|startswith|" in str(cond):
                    return self.startswith_expression.format(field=field, value=val.strip("*"))
                else:
                    return f"{field}:{val}"
            return f"{field}:{self.str_quote}{val}{self.str_quote}"
        except Exception as e:
            raise ValueError(f"Error converting string condition: {str(e)}")

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field equals numeric value expressions."""
        try:
            field = self.escape_and_quote_field(cond.field)
            return f"{field}:{cond.value}"
        except Exception as e:
            raise ValueError(f"Error converting numeric condition: {str(e)}")

    def convert_condition_field_eq_val_re(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert regular expression conditions."""
        try:
            field = self.escape_and_quote_field(cond.field)
            regex = self.escape_and_quote_regex(cond.value)
            return self.re_expression.format(field=field, regex=regex)
        except Exception as e:
            raise ValueError(f"Error converting regex condition: {str(e)}")

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert OR conditions."""
        try:
            if self.convert_or_as_in and self.can_convert_as_in_expression(cond):
                return self.convert_condition_as_in_expression(cond, state)
            
            expressions = []
            for arg in cond.args:
                expr = self.convert_condition(arg, state)
                if expr is not None:
                    expressions.append(expr)
            if not expressions:
                return None
            or_expr = f" {self.or_token} ".join(expressions)
            return self.group_expression.format(expr=or_expr) if len(expressions) > 1 else or_expr
        except Exception as e:
            raise ValueError(f"Error converting OR condition: {str(e)}")

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert AND conditions."""
        try:
            if self.convert_and_as_in and self.can_convert_as_in_expression(cond):
                return self.convert_condition_as_in_expression(cond, state)
            
            expressions = []
            for arg in cond.args:
                expr = self.convert_condition(arg, state)
                if expr is not None:
                    expressions.append(expr)
            if not expressions:
                return None
            and_expr = f" {self.and_token} ".join(expressions)
            return self.group_expression.format(expr=and_expr) if len(expressions) > 1 else and_expr
        except Exception as e:
            raise ValueError(f"Error converting AND condition: {str(e)}")

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert NOT conditions."""
        try:
            arg = cond.args[0]
            expr = self.convert_condition(arg, state)
            if expr is None:
                return None
            if isinstance(expr, DeferredQueryExpression):
                return expr.negate()
            
            # Handle nested conditions
            if arg.__class__ in self.precedence:
                return f"{self.not_token} ({expr})"
            return f"{self.not_token} {expr}"
        except Exception as e:
            raise ValueError(f"Error converting NOT condition: {str(e)}")

    def convert_condition_as_in_expression(self, cond: Union[ConditionOR, ConditionAND], state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert field in value list conditions."""
        try:
            field = self.escape_and_quote_field(cond.args[0].field)
            op = self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator
            
            values = []
            for arg in cond.args:
                if isinstance(arg, ConditionFieldEqualsValueExpression):
                    val = self.convert_value_str(arg.value, state)
                    if isinstance(arg.value, SigmaString) and arg.value.contains_special():
                        values.append(f"{val}")
                    else:
                        values.append(f'{self.str_quote}{val}{self.str_quote}')
            
            return self.field_in_list_expression.format(
                field=field,
                op=op,
                list=self.list_separator.join(values)
            )
        except Exception as e:
            raise ValueError(f"Error converting list condition: {str(e)}")

    def can_convert_as_in_expression(self, cond: Union[ConditionOR, ConditionAND]) -> bool:
        """Check if condition can be converted to in-expression."""
        if len(cond.args) < 2:
            return False
            
        fields = set()
        for arg in cond.args:
            if not isinstance(arg, ConditionFieldEqualsValueExpression):
                return False
            if not isinstance(arg.value, (SigmaString, SigmaNumber)):
                return False
            fields.add(arg.field)
        
        return len(fields) == 1

    def escape_and_quote_regex(self, regex: str) -> str:
        """Escape and quote regular expression."""
        escaped = regex
        if self.re_escape:
            for char in self.re_escape:
                escaped = escaped.replace(char, self.re_escape_char + char)
        if self.re_escape_escape_char:
            escaped = escaped.replace(self.re_escape_char, self.re_escape_char + self.re_escape_char)
        return escaped

    def finalize_query(self, rule: SigmaRule, query: Union[str, DeferredQueryExpression], index: int, state: ConversionState, output_format: str) -> Union[str, DeferredQueryExpression]:
        """Finalize query for output."""
        if isinstance(query, DeferredQueryExpression):
            return query
        
        if query is None:
            return ""
        
        # Clean up the query
        query = re.sub(r'\s+', ' ', query)  # Remove extra spaces
        query = query.replace(" AND ", " AND ")  # Normalize operators
        query = query.replace(" OR ", " OR ")
        query = query.replace(" NOT ", " NOT ")
        query = query.strip()  # Remove leading/trailing spaces
        
        # Handle different output formats
        if output_format == "default":
            return query
        
        return query