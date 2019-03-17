#include <utils/injector.h>
#include <iostream>
#include <memory>

int main(int /*argc*/, char** /*argv*/)
{
    using namespace ReTools::Utils;
    std::unique_ptr<Injector> spInjector;

    try
    {
        spInjector.reset(new Injector("UNIst.exe"));
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    if (!spInjector->InjectDll("unisthooks.dll"))
    {
        std::cerr << "Couldn't inject unisthooks.dll" << std::endl;
        return -1;
    }

    std::cout << "Successfully injected DLL" << std::endl;

    return 0;
}
