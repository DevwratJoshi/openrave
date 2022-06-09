// -*- coding: utf-8 -*-
// Copyright (C) 2022 Rosen Diankov (rdiankov@cs.cmu.edu)
//
// This file is part of OpenRAVE.
// OpenRAVE is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <cstdarg>
#include <cstring>
#include <fstream>
#include <condition_variable>
#include <functional>
#include <mutex>

#include <openrave/openraveexception.h>
#include <openrave/logging.h>

#ifdef HAVE_BOOST_FILESYSTEM
#include <boost/filesystem.hpp>
#endif
#include <boost/version.hpp>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define PLUGIN_EXT ".dll"
#define OPENRAVE_LAZY_LOADING false
#else
#define OPENRAVE_LAZY_LOADING true
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#ifdef __APPLE_CC__
#define PLUGIN_EXT ".dylib"
#else
#define PLUGIN_EXT ".so"
#endif

#endif

#ifndef INTERFACE_PREDELETER
#define INTERFACE_PREDELETER boost::function<void(void const*)>()
#endif
#ifndef INTERFACE_POSTDELETER
#define INTERFACE_POSTDELETER(name, plugin) boost::bind(&RaveDatabase::_InterfaceDestroyCallbackSharedPost,shared_from_this(),name,plugin)
#endif

#ifdef _WIN32
const char s_filesep = '\\';
const char* s_delimiter = ";";
#else
const char s_filesep = '/';
const char* s_delimiter = ":";
#endif

#include "libopenrave.h"
#include "plugindatabase.h"

namespace fs = boost::filesystem;

namespace OpenRAVE {

void* _SysLoadLibrary(const std::string& lib, bool bLazy)
{
    // check if file exists first
    if( !std::ifstream(lib.c_str()) ) {
        return NULL;
    }
#ifdef _WIN32
    void* plib = LoadLibraryA(lib.c_str());
    if( plib == NULL ) {
        RAVELOG_WARN("Failed to load %s\n", lib.c_str());
    }
#else
    dlerror();     // clear error
    void* plib = dlopen(lib.c_str(), bLazy ? RTLD_LAZY : RTLD_NOW);
    char* pstr = dlerror();
    if( pstr != NULL ) {
        RAVELOG_WARN("%s: %s\n",lib.c_str(),pstr);
        if( plib != NULL ) {
            dlclose(plib);     //???
        }
        return NULL;
    }
#endif
    return plib;
}

void* _SysLoadSym(void* lib, const std::string& sym)
{
#ifdef _WIN32
    return GetProcAddress((HINSTANCE)lib, sym.c_str());
#else
    dlerror();     // clear existing error
    void* psym = dlsym(lib, sym.c_str());
    char* errorstring = dlerror();
    if( errorstring != NULL ) {
        return psym;
    }
    if( psym != NULL ) {
        // check for errors if something valid is returned since we'll be executing it
        if( errorstring != NULL ) {
            throw openrave_exception(errorstring,ORE_InvalidPlugin);
        }
    }
    return psym;
#endif
}

void _SysCloseLibrary(void* lib)
{
#ifdef _WIN32
    FreeLibrary((HINSTANCE)lib);
#else
    // can segfault if opened library clashes with other
    // need to use some combination of setjmp, longjmp to get this to work corectly
    //sighandler_t tprev = signal(SIGSEGV,fault_handler);
    dlclose(lib);
    //signal(SIGSEGV,tprev);
#endif
}

Plugin::Plugin(boost::shared_ptr<RaveDatabase> pdatabase)
    : _pdatabase(pdatabase)
    , plibrary(NULL)
    , pfnCreateNew(NULL)
    , pfnGetPluginAttributesNew(NULL)
    , pfnDestroyPlugin(NULL)
    , pfnOnRaveInitialized(NULL)
    , pfnOnRavePreDestroy(NULL)
    , _bShutdown(false)
    , _bInitializing(true)
    , _bHasCalledOnRaveInitialized(false)
{
}

Plugin::~Plugin()
{
    Destroy();
}

bool Plugin::Init(const std::string& libraryname) {
    fs::path fullpath = fs::canonical(fs::path(libraryname));
    RAVELOG_INFO_FORMAT("Loading shared library at %s...\n", fullpath.c_str());

    // Try to resolve the path to a file, filling in missing filename parts when necessary.
    if (!fs::is_regular_file(fullpath)) {
        RAVELOG_WARN_FORMAT("Object at %s is not a file.\n", fullpath.c_str());
        return false;
    }

    if (!fs::exists(fullpath)) {
        // Try appending a '.so' if the path does not have one
        if (!fullpath.has_extension()) {
            fullpath = fs::path(fullpath.string() + PLUGIN_EXT);
        }
    }
    if (!fs::exists(fullpath)) {
        // Try prefixing the filename with 'lib'
        if (fullpath.filename().string().size() > 3 && fullpath.filename().string().substr(0, 3) != "lib") {
            fullpath = fullpath.parent_path() / ("lib" + fullpath.filename().string());
        }
    }
    if (!fs::exists(fullpath)) {
        RAVELOG_WARN_FORMAT("File at %s does not exist.\n", fullpath.c_str());
        return false;
    }
    plibrary = _SysLoadLibrary(fullpath.string(), OPENRAVE_LAZY_LOADING);
    if (plibrary == NULL) {
        // File is not loadable for some reason
        RAVELOG_WARN_FORMAT("File at %s could not be loaded as a shared object.\n", fullpath.c_str());
        return false;
    }
    ppluginname = fullpath.string();

    if (Load_GetPluginAttributes()) {
#ifndef _WIN32
        Dl_info info;
        dladdr((void*)pfnGetPluginAttributesNew, &info);
        RAVELOG_DEBUG_FORMAT("Loading plugin: %s\n", info.dli_fname);
#endif
    } else {
        // might not be a plugin
        RAVELOG_INFO_FORMAT("%s: can't load GetPluginAttributes function, might not be an OpenRAVE plugin\n", ppluginname);
        return false;
    }
    pfnGetPluginAttributesNew(&_infocached, sizeof(_infocached), OPENRAVE_PLUGININFO_HASH);
    _bInitializing = false;
    if (OPENRAVE_LAZY_LOADING) {
        // have confirmed that plugin is ok, so reload with no-lazy loading
        plibrary = NULL;     // NOTE: for some reason, closing the lazy loaded library can make the system crash, so instead keep the pointer around, but create a new one with RTLD_NOW
        Destroy();
        _bShutdown = false;
    }
    OnRaveInitialized();
    return true;
}

void Plugin::Destroy()
{
    if( _bInitializing ) {
        if( plibrary ) {
            if( OPENRAVE_LAZY_LOADING ) {
                // NOTE: for some reason, closing the lazy loaded library can make the system crash, so instead keep the memory around, and create a new one with RTLD_NOW if necessary
            }
            else {
                _SysCloseLibrary(plibrary);
            }
            plibrary = NULL;
        }
    }
    else {
        if( plibrary ) {
            Load_DestroyPlugin();
        }
        boost::mutex::scoped_lock lock(_mutex);
        // do some more checking here, there still might be instances of robots, planners, and sensors out there
        if (plibrary) {
            RAVELOG_INFO_FORMAT("RaveDatabase: closing plugin %s\n", ppluginname.c_str());        // Sleep(10);
            if( pfnDestroyPlugin != NULL ) {
                pfnDestroyPlugin();
            }
            boost::shared_ptr<RaveDatabase> pdatabase = _pdatabase.lock();
            if( !!pdatabase ) {
                pdatabase->_QueueLibraryDestruction(plibrary);
            }
            plibrary = NULL;
        }
    }
    pfnCreateNew = NULL;
    pfnDestroyPlugin = NULL;
    pfnOnRaveInitialized = NULL;
    pfnOnRavePreDestroy = NULL;
    pfnGetPluginAttributesNew = NULL;
    _bShutdown = true;
}

bool Plugin::IsValid()
{
    return !_bShutdown;
}

const std::string& Plugin::GetName() const
{
    return ppluginname;
}

bool Plugin::GetInfo(PLUGININFO& info)
{
    info = _infocached;
    return true;
}

bool Plugin::Load_CreateInterfaceGlobal()
{
    _confirmLibrary();
    if (pfnCreateNew == NULL) {
        pfnCreateNew = (PluginExportFn_OpenRAVECreateInterface)_SysLoadSym(plibrary, "OpenRAVECreateInterface");
    }
    return pfnCreateNew != NULL;
}

bool Plugin::Load_GetPluginAttributes()
{
    _confirmLibrary();
    if (pfnGetPluginAttributesNew == NULL) {
        pfnGetPluginAttributesNew = (PluginExportFn_OpenRAVEGetPluginAttributes)_SysLoadSym(plibrary,"OpenRAVEGetPluginAttributes");
    }
    return pfnGetPluginAttributesNew != NULL;
}

bool Plugin::Load_DestroyPlugin()
{
    _confirmLibrary();
    if( pfnDestroyPlugin == NULL ) {
#ifdef _MSC_VER
        pfnDestroyPlugin = (PluginExportFn_DestroyPlugin)_SysLoadSym(plibrary, "?DestroyPlugin@@YAXXZ");
#else
        pfnDestroyPlugin = (PluginExportFn_DestroyPlugin)_SysLoadSym(plibrary, "_Z13DestroyPluginv");
#endif
        if( pfnDestroyPlugin == NULL ) {
            pfnDestroyPlugin = (PluginExportFn_DestroyPlugin)_SysLoadSym(plibrary, "DestroyPlugin");
            if( pfnDestroyPlugin == NULL ) {
                RAVELOG_WARN_FORMAT("%s: can't load DestroyPlugin function, passing...\n", ppluginname);
                return false;
            }
        }
    }
    return pfnDestroyPlugin != NULL;
}

bool Plugin::Load_OnRaveInitialized()
{
    _confirmLibrary();
    if( pfnOnRaveInitialized == NULL ) {
#ifdef _MSC_VER
        pfnOnRaveInitialized = (PluginExportFn_OnRaveInitialized)_SysLoadSym(plibrary, "?OnRaveInitialized@@YAXXZ");
#else
        pfnOnRaveInitialized = (PluginExportFn_OnRaveInitialized)_SysLoadSym(plibrary, "_Z17OnRaveInitializedv");
#endif
        if( pfnOnRaveInitialized == NULL ) {
            pfnOnRaveInitialized = (PluginExportFn_OnRaveInitialized)_SysLoadSym(plibrary, "OnRaveInitialized");
            if( pfnOnRaveInitialized == NULL ) {
                //RAVELOG_VERBOSE(str(boost::format("%s: can't load OnRaveInitialized function, passing...\n")%ppluginname));
                return false;
            }
        }
    }
    return pfnOnRaveInitialized!=NULL;
}

bool Plugin::Load_OnRavePreDestroy()
{
    _confirmLibrary();
    if( pfnOnRavePreDestroy == NULL ) {
#ifdef _MSC_VER
        pfnOnRavePreDestroy = (PluginExportFn_OnRavePreDestroy)_SysLoadSym(plibrary, "?OnRavePreDestroy@@YAXXZ");
#else
        pfnOnRavePreDestroy = (PluginExportFn_OnRavePreDestroy)_SysLoadSym(plibrary, "_Z16OnRavePreDestroyv");
#endif
        if( pfnOnRavePreDestroy == NULL ) {
            pfnOnRavePreDestroy = (PluginExportFn_OnRavePreDestroy)_SysLoadSym(plibrary, "OnRavePreDestroy");
            if( pfnOnRavePreDestroy == NULL ) {
                //RAVELOG_VERBOSE(str(boost::format("%s: can't load OnRavePreDestroy function, passing...\n")%ppluginname));
                return false;
            }
        }
    }
    return pfnOnRavePreDestroy!=NULL;
}

bool Plugin::HasInterface(InterfaceType type, const std::string& name)
{
    if( name.size() == 0 ) {
        return false;
    }
    std::map<InterfaceType, std::vector<std::string> >::iterator itregisterednames = _infocached.interfacenames.find(type);
    if( itregisterednames == _infocached.interfacenames.end() ) {
        return false;
    }
    FOREACH(it,itregisterednames->second) {
        if(( name.size() >= it->size()) &&( _strnicmp(name.c_str(),it->c_str(),it->size()) == 0) ) {
            return true;
        }
    }
    return false;
}

InterfaceBasePtr Plugin::CreateInterface(InterfaceType type, const std::string& name, const char* interfacehash, EnvironmentBasePtr penv)
{
    std::pair<InterfaceType, std::string> p(type, utils::ConvertToLowerCase(name));
    if( _setBadInterfaces.find(p) != _setBadInterfaces.end() ) {
        return InterfaceBasePtr();
    }

    if( !HasInterface(type,name) ) {
        return InterfaceBasePtr();
    }

    try {
        if( !Load_CreateInterfaceGlobal() ) {
            throw openrave_exception(str(boost::format(_("%s: can't load CreateInterface function\n"))%ppluginname),ORE_InvalidPlugin);
        }
        InterfaceBasePtr pinterface = pfnCreateNew(type,name,interfacehash,OPENRAVE_ENVIRONMENT_HASH,penv);
        return pinterface;
    }
    catch(const openrave_exception& ex) {
        RAVELOG_ERROR_FORMAT("Create Interface: openrave exception , plugin %s: %s\n", ppluginname%ex.what());
        if( ex.GetCode() == ORE_InvalidPlugin ) {
            RAVELOG_DEBUG_FORMAT("shared object %s is not a valid openrave plugin\n", ppluginname);
            Destroy();
        }
        else if( ex.GetCode() == ORE_InvalidInterfaceHash ) {
            _setBadInterfaces.insert(p);
        }
    }
    catch(const std::exception& ex) {
        RAVELOG_ERROR_FORMAT("Create Interface: unknown exception, plugin %s: %s\n", ppluginname%ex.what());
    }
    catch(...) {
        RAVELOG_ERROR_FORMAT("Create Interface: unknown exception, plugin %s\n", ppluginname);
    }
    return InterfaceBasePtr();
}

void Plugin::OnRaveInitialized()
{
    if( Load_OnRaveInitialized() ) {
        if( !!pfnOnRaveInitialized && !_bHasCalledOnRaveInitialized ) {
            pfnOnRaveInitialized();
            _bHasCalledOnRaveInitialized = true;
        }
    }
}

void Plugin::OnRavePreDestroy()
{
    if( Load_OnRavePreDestroy() ) {
        // always call destroy regardless of initialization state (safest)
        if( !!pfnOnRavePreDestroy ) {
            pfnOnRavePreDestroy();
            _bHasCalledOnRaveInitialized = false;
        }
    }
}

void Plugin::_confirmLibrary()
{
    // first test the library before locking
    if( plibrary == NULL ) {
        boost::mutex::scoped_lock lock(_mutex);
        _pdatabase.lock()->_AddToLoader(shared_from_this());
        do {
            if( plibrary ) {
                return;
            }
            if( _bShutdown ) {
                throw openrave_exception(_("library is shutting down"),ORE_InvalidPlugin);
            }
            _cond.wait(lock);
        } while(1);
    }
}

RaveDatabase::RegisteredInterface::RegisteredInterface(InterfaceType type, const std::string& name, const boost::function<InterfaceBasePtr(EnvironmentBasePtr, std::istream&)>& createfn, boost::shared_ptr<RaveDatabase> database)
    : _type(type)
    , _name(name)
    , _createfn(createfn)
    , _database(database)
{
}

RaveDatabase::RegisteredInterface::~RegisteredInterface()
{
    boost::shared_ptr<RaveDatabase> database = _database.lock();
    if( !!database ) {
        boost::mutex::scoped_lock lock(database->_mutex);
        database->_listRegisteredInterfaces.erase(_iterator);
    }
}

RaveDatabase::RaveDatabase() : _bShutdown(false)
{
}

RaveDatabase::~RaveDatabase()
{
    Destroy();
}

bool RaveDatabase::Init(bool bLoadAllPlugins)
{
    _threadPluginLoader.reset(new boost::thread(boost::bind(&RaveDatabase::_PluginLoaderThread, this)));
    std::vector<std::string> vplugindirs;
    char* pOPENRAVE_PLUGINS = getenv("OPENRAVE_PLUGINS"); // getenv not thread-safe?
    if( pOPENRAVE_PLUGINS != NULL ) {
        utils::TokenizeString(pOPENRAVE_PLUGINS, s_delimiter, vplugindirs);
    }
    for (int iplugindir = vplugindirs.size() - 1; iplugindir > 0; iplugindir--) {
        int jplugindir = 0;
        for(; jplugindir < iplugindir; jplugindir++) {
            if(vplugindirs[iplugindir] == vplugindirs[jplugindir]) {
                break;
            }
        }
        if (jplugindir < iplugindir) {
            vplugindirs.erase(vplugindirs.begin()+iplugindir);
        }
    }
    bool bExists = false;
    std::string installdir = OPENRAVE_PLUGINS_INSTALL_DIR;
#ifdef HAVE_BOOST_FILESYSTEM
    if( !boost::filesystem::is_directory(boost::filesystem::path(installdir)) ) {
#ifdef _WIN32
        HKEY hkey;
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\OpenRAVE\\" OPENRAVE_VERSION_STRING), 0, KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS) {
            DWORD dwType = REG_SZ;
            CHAR szInstallRoot[4096];     // dont' take chances, it is windows
            DWORD dwSize = sizeof(szInstallRoot);
            RegQueryValueEx(hkey, TEXT("InstallRoot"), NULL, &dwType, (PBYTE)szInstallRoot, &dwSize);
            RegCloseKey(hkey);
            installdir.assign(szInstallRoot);
            installdir += str(boost::format("%cshare%copenrave-%d.%d%cplugins")%s_filesep%s_filesep%OPENRAVE_VERSION_MAJOR%OPENRAVE_VERSION_MINOR%s_filesep);
            RAVELOG_VERBOSE(str(boost::format("window registry plugin dir '%s'")%installdir));
        }
        else
#endif
        {
            RAVELOG_WARN_FORMAT("%s doesn't exist", installdir);
        }
    }
    boost::filesystem::path pluginsfilename = boost::filesystem::absolute(boost::filesystem::path(installdir));
    FOREACH(itname, vplugindirs) {
        if( pluginsfilename == boost::filesystem::absolute(boost::filesystem::path(*itname)) ) {
            bExists = true;
            break;
        }
    }
#else
    std::string pluginsfilename=installdir;
    FOREACH(itname, vplugindirs) {
        if( pluginsfilename == *itname ) {
            bExists = true;
            break;
        }
    }
#endif
    if( !bExists ) {
        vplugindirs.push_back(installdir);
    }
    FOREACH(it, vplugindirs) {
        if( it->size() > 0 ) {
            _listplugindirs.push_back(*it);
            RAVELOG_INFO_FORMAT("plugin dir: %s", (*it));
        }
    }
    if( bLoadAllPlugins ) {
        FOREACH(it, vplugindirs) {
            if( it->size() > 0 ) {
                AddDirectory(*it);
            }
        }
    }
    return true;
}

void RaveDatabase::Destroy()
{
    RAVELOG_DEBUG("plugin database shutting down...\n");
    {
        boost::mutex::scoped_lock lock(_mutexPluginLoader);
        _bShutdown = true;
        _condLoaderHasWork.notify_all();
    }
    if( !!_threadPluginLoader ) {
        _threadPluginLoader->join();
        _threadPluginLoader.reset();
    }
    {
        boost::mutex::scoped_lock lock(_mutex);
        _listplugins.clear();
    }
    // cannot lock mutex due to __erase_iterator
    // cannot clear _listRegisteredInterfaces since there are destructors that will remove items from the list
    //_listRegisteredInterfaces.clear();
    {
        boost::mutex::scoped_lock lock(_mutex);
        _CleanupUnusedLibraries();
    }
    _listplugindirs.clear();
    RAVELOG_DEBUG("openrave plugin database destroyed\n");
}

void RaveDatabase::GetPlugins(std::list<PluginPtr>& listplugins) const
{
    boost::mutex::scoped_lock lock(_mutex);
    listplugins = _listplugins;
}

InterfaceBasePtr RaveDatabase::Create(EnvironmentBasePtr penv, InterfaceType type, const std::string& _name)
{
    std::string name=_name;
    InterfaceBasePtr pointer;
    if( name.size() == 0 ) {
        switch(type) {
        case PT_KinBody: {
            pointer.reset(new KinBody(PT_KinBody,penv));
            pointer->__strxmlid = ""; // don't set to KinBody since there's no officially registered interface
            break;
        }
        case PT_PhysicsEngine: name = "GenericPhysicsEngine"; break;
        case PT_CollisionChecker: name = "GenericCollisionChecker"; break;
        case PT_Robot: name = "GenericRobot"; break;
        case PT_Trajectory: name = "GenericTrajectory"; break;
        default: break;
        }
    }

    if( !pointer ) {
        size_t nInterfaceNameLength = name.find_first_of(' ');
        if( nInterfaceNameLength == std::string::npos ) {
            nInterfaceNameLength = name.size();
        }
        if( nInterfaceNameLength == 0 ) {
            RAVELOG_WARN_FORMAT("interface %s name \"%s\" needs to start with a valid character\n", RaveGetInterfaceName(type) % name);
            return InterfaceBasePtr();
        }

        // have to copy in order to allow plugins to register stuff inside their creation methods
        std::list< boost::weak_ptr<RegisteredInterface> > listRegisteredInterfaces;
        std::list<PluginPtr> listplugins;
        {
            boost::mutex::scoped_lock lock(_mutex);
            listRegisteredInterfaces = _listRegisteredInterfaces;
            listplugins = _listplugins;
        }
        FOREACH(it, listRegisteredInterfaces) {
            RegisteredInterfacePtr registration = it->lock();
            if( !!registration ) {
                if(( nInterfaceNameLength >= registration->_name.size()) &&( _strnicmp(name.c_str(),registration->_name.c_str(),registration->_name.size()) == 0) ) {
                    std::stringstream sinput(name);
                    std::string interfacename;
                    sinput >> interfacename;
                    std::transform(interfacename.begin(), interfacename.end(), interfacename.begin(), ::tolower);
                    pointer = registration->_createfn(penv,sinput);
                    if( !!pointer ) {
                        if( pointer->GetInterfaceType() != type ) {
                            RAVELOG_FATAL_FORMAT("plugin interface name %s, type %s, types do not match\n", name%RaveGetInterfaceName(type));
                            pointer.reset();
                        }
                        else {
                            pointer = InterfaceBasePtr(pointer.get(), utils::smart_pointer_deleter<InterfaceBasePtr>(pointer,INTERFACE_PREDELETER));
                            pointer->__strpluginname = "__internal__";
                            pointer->__strxmlid = name;
                            //pointer->__plugin; // need to protect resources?
                            break;
                        }
                    }
                }
            }
        }

        if( !pointer ) {
            const char* hash = RaveGetInterfaceHash(type);
            std::list<PluginPtr>::iterator itplugin = listplugins.begin();
            while(itplugin != listplugins.end()) {
                pointer = (*itplugin)->CreateInterface(type, name, hash, penv);
                if( !!pointer ) {
                    if( strcmp(pointer->GetHash(), hash) ) {
                        RAVELOG_FATAL_FORMAT("plugin interface name %s, %s has invalid hash, might be compiled with stale openrave files\n", name%RaveGetInterfaceName(type));
                        (*itplugin)->_setBadInterfaces.insert(std::make_pair(type,utils::ConvertToLowerCase(name)));
                        pointer.reset();
                    }
                    else if( pointer->GetInterfaceType() != type ) {
                        RAVELOG_FATAL_FORMAT("plugin interface name %s, type %s, types do not match\n", name%RaveGetInterfaceName(type));
                        (*itplugin)->_setBadInterfaces.insert(std::make_pair(type,utils::ConvertToLowerCase(name)));
                        pointer.reset();
                    }
                    else {
                        pointer = InterfaceBasePtr(pointer.get(), utils::smart_pointer_deleter<InterfaceBasePtr>(pointer,INTERFACE_PREDELETER, INTERFACE_POSTDELETER(name, *itplugin)));
                        pointer->__strpluginname = (*itplugin)->ppluginname;
                        pointer->__strxmlid = name;
                        pointer->__plugin = *itplugin;
                        break;
                    }
                }
                if( !(*itplugin)->IsValid() ) {
                    boost::mutex::scoped_lock lock(_mutex);
                    _listplugins.remove(*itplugin);
                }
                ++itplugin;
            }
        }
    }

    if( !!pointer ) {
        if( type == PT_Robot ) {
            RobotBasePtr probot = RaveInterfaceCast<RobotBase>(pointer);
            if( strcmp(probot->GetKinBodyHash(), OPENRAVE_KINBODY_HASH) ) {
                RAVELOG_FATAL_FORMAT("plugin interface Robot, name %s has invalid hash, might be compiled with stale openrave files", name);
                pointer.reset();
            }
            if( !probot->IsRobot() ) {
                RAVELOG_FATAL_FORMAT("interface Robot, name %s should have IsRobot() return true", name);
                pointer.reset();
            }
        }
    }
    if( !pointer ) {
        RAVELOG_WARN_FORMAT("env=%d failed to create name %s, interface %s\n", penv->GetId()%name%RaveGetInterfaceNamesMap().find(type)->second);
    }
    return pointer;
}

bool RaveDatabase::AddDirectory(const std::string& pdir)
{
#ifdef _WIN32
    WIN32_FIND_DATAA FindFileData;
    HANDLE hFind;
    std::string strfind = pdir;
    strfind += "\\*";
    strfind += PLUGIN_EXT;

    hFind = FindFirstFileA(strfind.c_str(), &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        RAVELOG_DEBUG("No plugins in dir: %s (GetLastError reports %d)\n", pdir.c_str(), GetLastError ());
        return false;
    }
    else  {
        do {
            RAVELOG_DEBUG("Adding plugin %s\n", FindFileData.cFileName);
            std::string strplugin = pdir;
            strplugin += "\\";
            strplugin += FindFileData.cFileName;
            LoadPlugin(strplugin);
        } while (FindNextFileA(hFind, &FindFileData) != 0);
        FindClose(hFind);
    }
#else
    // linux
    DIR *dp;
    struct dirent *ep;
    dp = opendir (pdir.c_str());
    if (dp != NULL) {
        while ( (ep = readdir (dp)) != NULL ) {
            // check for a .so in every file
            // check that filename ends with .so
            if( strlen(ep->d_name) >= strlen(PLUGIN_EXT) &&
                strcmp(ep->d_name + strlen(ep->d_name) - strlen(PLUGIN_EXT), PLUGIN_EXT) == 0 ) {
                std::string strplugin = pdir;
                strplugin += "/";
                strplugin += ep->d_name;
                LoadPlugin(strplugin);
            }
        }
        (void) closedir (dp);
    }
    else {
        RAVELOG_INFO_FORMAT("Couldn't open directory %s\n", pdir.c_str());
    }
#endif
    return true;
}

void RaveDatabase::ReloadPlugins()
{
    boost::mutex::scoped_lock lock(_mutex);
    FOREACH(itplugin,_listplugins) {
        PluginPtr newplugin = boost::make_shared<Plugin>(shared_from_this());
        if( newplugin->Init((*itplugin)->ppluginname) ) {
            *itplugin = newplugin;
        }
    }
    _CleanupUnusedLibraries();
}

void RaveDatabase::OnRaveInitialized()
{
    boost::mutex::scoped_lock lock(_mutex);
    FOREACH(itplugin, _listplugins) {
        (*itplugin)->OnRaveInitialized();
    }
}

void RaveDatabase::OnRavePreDestroy()
{
    boost::mutex::scoped_lock lock(_mutex);
    FOREACH(itplugin, _listplugins) {
        (*itplugin)->OnRavePreDestroy();
    }
}

bool RaveDatabase::LoadPlugin(std::string pluginname)
{
    boost::mutex::scoped_lock lock(_mutex);
    PluginPtr plugin = _GetPlugin(pluginname);
    if( plugin ) {
        // since we got a match, use the old name and remove the old library
        pluginname = plugin->ppluginname;
        _listplugins.remove(plugin);
    }
    PluginPtr p = boost::make_shared<Plugin>(shared_from_this());
    if( p->Init(pluginname) ) {
        _listplugins.push_back(p);
        _CleanupUnusedLibraries();
        return true;
    }
    _CleanupUnusedLibraries();
    return false;
}

/// \brief Deletes the plugin from the database
///
/// It is safe to delete a plugin even if interfaces currently reference it because this function just decrements
/// the reference count instead of unloading from memory.
bool RaveDatabase::RemovePlugin(const std::string& pluginname)
{
    boost::mutex::scoped_lock lock(_mutex);
    PluginPtr plugin = _GetPlugin(pluginname);
    if( !plugin ) {
        return false;
    }
    _listplugins.remove(plugin);
    _CleanupUnusedLibraries();
    return true;
}

bool RaveDatabase::HasInterface(InterfaceType type, const std::string& interfacename)
{
    boost::mutex::scoped_lock lock(_mutex);
    FOREACHC(it,_listRegisteredInterfaces) {
        RegisteredInterfacePtr registration = it->lock();
        if( !!registration ) {
            if(( interfacename.size() >= registration->_name.size()) &&( _strnicmp(interfacename.c_str(),registration->_name.c_str(),registration->_name.size()) == 0) ) {
                return true;
            }
        }
    }
    FOREACHC(itplugin, _listplugins) {
        if( (*itplugin)->HasInterface(type,interfacename) ) {
            return true;
        }
    }
    return false;
}

void RaveDatabase::GetPluginInfo(std::list< std::pair<std::string, PLUGININFO> >& plugins) const
{
    plugins.clear();
    boost::mutex::scoped_lock lock(_mutex);
    FOREACHC(itplugin, _listplugins) {
        PLUGININFO info;
        if( (*itplugin)->GetInfo(info) ) {
            plugins.emplace_back((*itplugin)->GetName(),info);
        }
    }
    if( !_listRegisteredInterfaces.empty() ) {
        plugins.emplace_back("__internal__", PLUGININFO());
        plugins.back().second.version = OPENRAVE_VERSION;
        FOREACHC(it,_listRegisteredInterfaces) {
            RegisteredInterfacePtr registration = it->lock();
            if( !!registration ) {
                plugins.back().second.interfacenames[registration->_type].push_back(registration->_name);
            }
        }
    }
}

void RaveDatabase::GetLoadedInterfaces(std::map<InterfaceType, std::vector<std::string> >& interfacenames) const
{
    interfacenames.clear();
    boost::mutex::scoped_lock lock(_mutex);
    FOREACHC(it,_listRegisteredInterfaces) {
        RegisteredInterfacePtr registration = it->lock();
        if( !!registration ) {
            interfacenames[registration->_type].push_back(registration->_name);
        }
    }
    FOREACHC(itplugin, _listplugins) {
        PLUGININFO localinfo;
        if( !(*itplugin)->GetInfo(localinfo) ) {
            RAVELOG_WARN_FORMAT("failed to get plugin info: %s\n", (*itplugin)->GetName());
        }
        else {
            // for now just return the cached info (so quering is faster)
            FOREACH(it,localinfo.interfacenames) {
                std::vector<std::string>& vnames = interfacenames[it->first];
                vnames.insert(vnames.end(),it->second.begin(),it->second.end());
            }
        }
    }
}

UserDataPtr RaveDatabase::RegisterInterface(InterfaceType type, const std::string& name, const char* interfacehash, const char* envhash, const boost::function<InterfaceBasePtr(EnvironmentBasePtr, std::istream&)>& createfn)
{
    BOOST_ASSERT(interfacehash != NULL && envhash != NULL);
    BOOST_ASSERT(!!createfn);
    BOOST_ASSERT(name.size()>0);
    if( strcmp(envhash, OPENRAVE_ENVIRONMENT_HASH) ) {
        throw openrave_exception(str(boost::format(_("environment invalid hash %s!=%s\n"))%envhash%OPENRAVE_ENVIRONMENT_HASH),ORE_InvalidInterfaceHash);
    }
    if( strcmp(interfacehash, RaveGetInterfaceHash(type)) ) {
        throw openrave_exception(str(boost::format(_("interface %s invalid hash %s!=%s\n"))%RaveGetInterfaceName(type)%interfacehash%RaveGetInterfaceHash(type)),ORE_InvalidInterfaceHash);
    }
    boost::mutex::scoped_lock lock(_mutex);
    RegisteredInterfacePtr pdata(new RegisteredInterface(type,name,createfn,shared_from_this()));
    pdata->_iterator = _listRegisteredInterfaces.insert(_listRegisteredInterfaces.end(),pdata);
    return pdata;
}

void RaveDatabase::_CleanupUnusedLibraries()
{
    FOREACH(it,_listDestroyLibraryQueue) {
        _SysCloseLibrary(*it);
    }
    _listDestroyLibraryQueue.clear();
}

PluginPtr RaveDatabase::_GetPlugin(const std::string& pluginname)
{
    for (PluginPtr ptr : _listplugins) {
        if (ptr->ppluginname == pluginname) {
            return ptr;
        }
#if defined(HAVE_BOOST_FILESYSTEM)
        else if (fs::path(pluginname).stem() == fs::path(ptr->ppluginname).stem()) {
            return ptr;
        }
#endif
    }
    return PluginPtr();
}

void RaveDatabase::_QueueLibraryDestruction(void* lib)
{
    _listDestroyLibraryQueue.push_back(lib);
}

void RaveDatabase::_InterfaceDestroyCallbackShared(void const* pinterface)
{
    if( pinterface != NULL ) {
    }
}

/// \brief makes sure plugin is in scope until after pointer is completely deleted
void RaveDatabase::_InterfaceDestroyCallbackSharedPost(std::string name, UserDataPtr plugin)
{
    // post-processing for deleting interfaces
    plugin.reset();
}

void RaveDatabase::_AddToLoader(PluginPtr p)
{
    boost::mutex::scoped_lock lock(_mutexPluginLoader);
    _listPluginsToLoad.push_back(p);
    _condLoaderHasWork.notify_all();
}

void RaveDatabase::_PluginLoaderThread()
{
    while(!_bShutdown) {
        std::list<PluginPtr> listPluginsToLoad;
        {
            boost::mutex::scoped_lock lock(_mutexPluginLoader);
            if( _listPluginsToLoad.empty() ) {
                _condLoaderHasWork.wait(lock);
                if( _bShutdown ) {
                    break;
                }
            }
            listPluginsToLoad.swap(_listPluginsToLoad);
        }
        FOREACH(itplugin,listPluginsToLoad) {
            if( _bShutdown ) {
                break;
            }
            boost::mutex::scoped_lock lockplugin((*itplugin)->_mutex);
            if( _bShutdown ) {
                break;
            }
            (*itplugin)->plibrary = _SysLoadLibrary((*itplugin)->ppluginname,false);
            if( (*itplugin)->plibrary == NULL ) {
                // for some reason cannot load the library, so shut it down
                (*itplugin)->_bShutdown = true;
            }
            (*itplugin)->_cond.notify_all();
        }
    }
}

} // namespace OpenRAVE