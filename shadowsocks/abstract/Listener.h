#pragma once
#include "Session.h"

class Listener
{
public:
    virtual void removeSession(Session* session) = 0;
};
