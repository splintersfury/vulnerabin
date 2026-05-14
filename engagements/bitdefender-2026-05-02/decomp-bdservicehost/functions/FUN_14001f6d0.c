char * FUN_14001f6d0(undefined4 param_1)

{
  switch(param_1) {
  case 0:
    return "<uninitialized>";
  case 1:
    return "true literal";
  case 2:
    return "false literal";
  case 3:
    return "null literal";
  case 4:
    return "string literal";
  case 5:
  case 6:
  case 7:
    return "number literal";
  case 8:
    return "\'[\'";
  case 9:
    return "\'{\'";
  case 10:
    return "\']\'";
  case 0xb:
    return "\'}\'";
  case 0xc:
    return "\':\'";
  case 0xd:
    return "\',\'";
  case 0xe:
    return "<parse error>";
  case 0xf:
    return "end of input";
  case 0x10:
    return "\'[\', \'{\', or a literal";
  default:
    return "unknown token";
  }
}


// FUNCTION_END

// FUNCTION_START: FUN_14001f7c0 @ 14001f7c0