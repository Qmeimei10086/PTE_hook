#pragma once
#include "pageUtils.h"

void logger(const char* info, bool is_err, LONG err_code);

bool isolation_pages(HANDLE process_id, void* va);