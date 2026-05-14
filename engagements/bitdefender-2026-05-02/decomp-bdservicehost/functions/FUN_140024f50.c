undefined8 FUN_140024f50(undefined8 *param_1)

{
  return CONCAT71((int7)((ulonglong)*param_1 >> 8),
                  (*(uint *)*param_1 & 1 << ((byte)param_1[1] & 0x1f)) != 0);
}


// FUNCTION_END

// FUNCTION_START: FUN_140024f70 @ 140024f70