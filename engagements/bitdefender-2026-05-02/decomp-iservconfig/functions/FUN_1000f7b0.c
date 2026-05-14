char * __fastcall FUN_1000f7b0(undefined1 *param_1)

{
  switch(*param_1) {
  case 0:
    return "null";
  case 1:
    return "object";
  case 2:
    return "array";
  case 3:
    return "string";
  case 4:
    return "boolean";
  default:
    return "number";
  case 8:
    return "discarded";
  }
}


// FUNCTION_END

// FUNCTION_START: FUN_1000f810 @ 1000f810