// -*- coding: utf-8 -*-
// Copyright (C) 2006-2010 Rosen Diankov (rdiankov@cs.cmu.edu)
//
// This program is free software: you can redistribute it and/or modify
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
#ifndef OPENRAVE_BASELASER_H
#define OPENRAVE_BASELASER_H

/// Laser rotates around the zaxis and it's 0 angle is pointed toward the xaxis.
class BaseLaser2DSensor : public SensorBase
{
protected:
    class BaseLaser2DXMLReader : public BaseXMLReader
    {
    public:
    BaseLaser2DXMLReader(boost::shared_ptr<BaseLaser2DSensor> psensor) : _psensor(psensor) {}
        
        virtual ProcessElement startElement(const std::string& name, const std::list<std::pair<std::string,std::string> >& atts)
        {
            if( !!_pcurreader ) {
                if( _pcurreader->startElement(name,atts) == PE_Support )
                    return PE_Support;
                return PE_Ignore;
            }

            if( name != "sensor" && name != "minangle" && name != "maxangle" && name != "maxrange" && name != "scantime" && name != "color" && name != "resolution" ) {
                return PE_Pass;
            }
            ss.str("");
            return PE_Support;
        }

        virtual bool endElement(const std::string& name)
        {    
            if( !!_pcurreader ) {
                if( _pcurreader->endElement(name) )
                    _pcurreader.reset();
                return false;
            }
            else if( name == "sensor" )
                return true;
            else if( name == "minangle" ) {
                ss >> _psensor->_pgeom->min_angle[0];
                if( !!ss )
                    _psensor->_pgeom->min_angle[0] *= PI/180.0f; // convert to radians
            }
            else if( name == "maxangle" ) {
                ss >> _psensor->_pgeom->max_angle[0];
                if( !!ss )
                    _psensor->_pgeom->max_angle[0] *= PI/180.0f; // convert to radians
            }
            else if( name == "resolution" ) {
                ss >> _psensor->_pgeom->resolution[0];
                if( !!ss )
                    _psensor->_pgeom->resolution[0] *= PI/180.0f; // convert to radians
            }
            else if( name == "maxrange" ) {
                ss >> _psensor->_pgeom->max_range;
            }
            else if( name == "scantime" ) {
                ss >> _psensor->fScanTime;
            }
            else if( name == "color" ) {
                ss >> _psensor->_vColor.x >> _psensor->_vColor.y >> _psensor->_vColor.z;
                // ok if not everything specified
                if( !ss )
                    ss.clear();
            }
            else
                RAVELOG_WARNA(str(boost::format("bad tag: %s")%name));

            if( !ss )
                RAVELOG_WARNA(str(boost::format("error parsing %s\n")%name));

            return false;
        }

        virtual void characters(const std::string& ch)
        {
            if( !!_pcurreader )
                _pcurreader->characters(ch);
            else {
                ss.clear();
                ss << ch;
            }
        }

    protected:
        BaseXMLReaderPtr _pcurreader;
        boost::shared_ptr<BaseLaser2DSensor> _psensor;
        stringstream ss;
    };

public:
    static BaseXMLReaderPtr CreateXMLReader(InterfaceBasePtr ptr, const std::list<std::pair<std::string,std::string> >& atts)
    {
        return BaseXMLReaderPtr(new BaseLaser2DXMLReader(boost::dynamic_pointer_cast<BaseLaser2DSensor>(ptr)));
    }

 BaseLaser2DSensor(EnvironmentBasePtr penv) : SensorBase(penv) {
        __description = ":Interface Author: Rosen Diankov\nProvides a simulated 2D laser range finder.";
        RegisterCommand("render",boost::bind(&BaseLaser2DSensor::_Render,this,_1,_2),
                        "Set rendering of the plots (1 or 0).");
        RegisterCommand("collidingbodies",boost::bind(&BaseLaser2DSensor::_CollidingBodies,this,_1,_2),
                        "Returns the ids of the bodies that the laser beams have hit.");

        _pgeom.reset(new LaserGeomData());
        _pdata.reset(new LaserSensorData());
        _bRender = false;
        _pgeom->min_angle[0] = -PI/2; _pgeom->min_angle[1] = 0;
        _pgeom->max_angle[0] = PI/2; _pgeom->max_angle[1] = 0;
        _pgeom->resolution[0] = 0.01f; _pgeom->resolution[1] = 0;
        _pgeom->max_range = 100;
        fTimeToScan = 0;
        _vColor = RaveVector<float>(0.5f,0.5f,1,1);
        _report.reset(new CollisionReport());
    }
    ~BaseLaser2DSensor() { Reset(0); }
    
    virtual bool Init(const string& args)
    {
        Reset(0);
        return true;
    }

    virtual void Reset(int options)
    {
        _listGraphicsHandles.clear();
        _iconhandle.reset();

        int N = (int)( (_pgeom->max_angle[0]-_pgeom->min_angle[0])/_pgeom->resolution[0] + 0.5f)+1;
    
        _pdata->positions.clear();
        _pdata->ranges.resize(N);
        _pdata->intensity.resize(N);
        _databodyids.resize(N);

        FOREACH(it, _pdata->ranges)
            *it = Vector(0,0,0);
        FOREACH(it, _pdata->intensity)
            *it = 0;
    }

    virtual bool SimulationStep(dReal fTimeElapsed)
    {
        fTimeToScan -= fTimeElapsed;
        if( fTimeToScan <= 0 ) {
            fTimeToScan = fScanTime;
            Vector rotaxis(0,0,1);
            Transform trot;
            RAY r;
    
            GetEnv()->GetCollisionChecker()->SetCollisionOptions(CO_Distance);
            Transform t;

            {
                // Lock the data mutex and fill with the range data (get all in one timestep)
                boost::mutex::scoped_lock lock(_mutexdata);
                _pdata->t = GetTransform();
                _pdata->__stamp = GetEnv()->GetSimulationTime();
        
                t = GetLaserPlaneTransform();
                r.pos = t.trans;

                size_t index = 0;
                for(float frotangle = _pgeom->min_angle[0]; frotangle <= _pgeom->max_angle[0]; frotangle += _pgeom->resolution[0], ++index) {
                    if( index >= _pdata->ranges.size() )
                        break;
            
                    trot.rotfromaxisangle(rotaxis, (dReal)frotangle);
                    Vector vdir(t.rotate(trot.rotate(Vector(1,0,0))));
                    r.dir = _pgeom->max_range*vdir;
                    
                    if( GetEnv()->CheckCollision(r, _report)) {
                        _pdata->ranges[index] = vdir*max(dReal(0.0001f),_report->minDistance);
                        _pdata->intensity[index] = 1;
                        // store the colliding bodies
                        KinBody::LinkConstPtr plink = !!_report->plink1 ? _report->plink1 : _report->plink2;
                        if( !!plink )
                            _databodyids[index] = plink->GetParent()->GetEnvironmentId();
                    }
                    else {
                        _databodyids[index] = 0;
                        _pdata->ranges[index] = vdir*_pgeom->max_range;
                        _pdata->intensity[index] = 0;
                    }
                }
            }

            GetEnv()->GetCollisionChecker()->SetCollisionOptions(0);
    
            if( _bRender ) {

                // If can render, check if some time passed before last update
                list<EnvironmentBase::GraphHandlePtr> listhandles;
                int N = 0;
                vector<RaveVector<float> > vpoints;
                vector<int> vindices;

                {
                    // Lock the data mutex and fill the arrays used for rendering
                    boost::mutex::scoped_lock lock(_mutexdata);
                    N = (int)_pdata->ranges.size();
                    vpoints.resize(N+1);
                    for(int i = 0; i < N; ++i)
                        vpoints[i] = _pdata->ranges[i] + t.trans;
                    vpoints[N] = t.trans;
                }

                // render the transparent fan
                vindices.resize(3*(N-1));
            
                for(int i = 0; i < N-1; ++i) {
                    vindices[3*i+0] = i;
                    vindices[3*i+1] = i+1;
                    vindices[3*i+2] = N;
                }

                _vColor.w = 1;
                // Render points at each measurement, and a triangle fan for the entire free surface of the laser
                listhandles.push_back(GetEnv()->plot3(&vpoints[0].x, N, sizeof(vpoints[0]), 5.0f, _vColor));
            
                _vColor.w = 0.2f;
                listhandles.push_back(GetEnv()->drawtrimesh(vpoints[0], sizeof(vpoints[0]), &vindices[0], N-1, _vColor));
            
                // close the old graphs last to avoid flickering
                _listGraphicsHandles.swap(listhandles);

            }
            else {
                _listGraphicsHandles.clear();
            }

            _report->Reset();
        }

        return true;
    }

    virtual SensorGeometryPtr GetSensorGeometry()
    {
        LaserGeomData* pgeom = new LaserGeomData();
        *pgeom = *_pgeom;
        return SensorGeometryPtr(pgeom);
    }

    virtual SensorDataPtr CreateSensorData()
    {
        return SensorDataPtr(new LaserSensorData());
    }

    virtual bool GetSensorData(SensorDataPtr psensordata)
    {
        boost::mutex::scoped_lock lock(_mutexdata);
        *boost::dynamic_pointer_cast<LaserSensorData>(psensordata) = *_pdata;
        return true;
    }

    bool _Render(ostream& sout, istream& sinput)
    {
        sinput >> _bRender;
        return !!sinput;
    }
    bool _CollidingBodies(ostream& sout, istream& sinput)
    {
        boost::mutex::scoped_lock lock(_mutexdata);
        FOREACH(it, _databodyids) {
            sout << *it << " ";
        }
        return true;
    }

    virtual void SetTransform(const Transform& trans)
    {
        _trans = trans;
        Transform t = GetLaserPlaneTransform();
    
        int N = 10;
        viconpoints.resize(N+2);
        viconindices.resize(3*N);
        viconpoints[0] = t.trans;
        Transform trot;

        for(int i = 0; i <= N; ++i) {
            dReal fang = _pgeom->min_angle[0] + (_pgeom->max_angle[0]-_pgeom->min_angle[0])*(float)i/(float)N;
            trot.rotfromaxisangle(Vector(0,0,1), fang);
            viconpoints[i+1] = t * trot.rotate(Vector(0.05f,0,0));

            if( i < N ) {
                viconindices[3*i+0] = 0;
                viconindices[3*i+1] = i+1;
                viconindices[3*i+2] = i+2;
            }
        }

        RaveVector<float> vcolor = _vColor*0.5f;
        vcolor.w = 0.7f;
        _iconhandle = GetEnv()->drawtrimesh(viconpoints[0], sizeof(viconpoints[0]), &viconindices[0], N, vcolor);
    }

    virtual Transform GetTransform() { return _trans; }

protected:

    virtual Transform GetLaserPlaneTransform() { return _trans; }

    boost::shared_ptr<LaserGeomData> _pgeom;
    boost::shared_ptr<LaserSensorData> _pdata;
    vector<int> _databodyids; ///< if non 0, for each point in _data, specifies the body that was hit
    CollisionReportPtr _report;

    // more geom stuff
    dReal _fGeomMinRange;
    RaveVector<float> _vColor;

    Transform _trans;
    list<EnvironmentBase::GraphHandlePtr> _listGraphicsHandles;
    EnvironmentBase::GraphHandlePtr _iconhandle;
    vector<RaveVector<float> > viconpoints;
    vector<int> viconindices;
    dReal fTimeToScan, fScanTime;

    boost::mutex _mutexdata;
    bool _bRender;

    friend class BaseLaser2DXMLReader;
};

class BaseSpinningLaser2DSensor : public BaseLaser2DSensor
{
protected:
    class BaseSpinningLaser2DXMLReader : public BaseLaser2DXMLReader
    {
    public:
  BaseSpinningLaser2DXMLReader(boost::shared_ptr<BaseSpinningLaser2DSensor> psensor) : BaseLaser2DXMLReader(psensor), _bProcessing(false) {}

        virtual ProcessElement startElement(const std::string& name, const std::list<std::pair<std::string,std::string> >& atts)
        {
            if( _bProcessing )
                return PE_Ignore;
            switch( BaseLaser2DXMLReader::startElement(name,atts) ) {
                case PE_Pass: break;
                case PE_Support: return PE_Support;
                case PE_Ignore: return PE_Ignore;
            }

            _bProcessing = name == "spinaxis" || name == "spinpos" || name == "spinspeed";
            return _bProcessing ? PE_Support : PE_Pass;
        }

        virtual bool endElement(const string& name)
        {
            if( _bProcessing ) {
                boost::shared_ptr<BaseSpinningLaser2DSensor> psensor = boost::dynamic_pointer_cast<BaseSpinningLaser2DSensor>(_psensor);
            
                if( name == "spinaxis" )
                    ss >> psensor->_vGeomSpinAxis.x >> psensor->_vGeomSpinAxis.y >> psensor->_vGeomSpinAxis.z;
                else if( name == "spinpos" )
                    ss >> psensor->_vGeomSpinPos.x >> psensor->_vGeomSpinPos.y >> psensor->_vGeomSpinPos.z;
                else if( name == "spinspeed" )
                    ss >> psensor->_fGeomSpinSpeed;
                else
                    RAVELOG_WARN("invalid tag\n");
                if( !ss )
                    RAVELOG_WARNA(str(boost::format("error parsing %s\n")%name));
                _bProcessing = false;
                return false;
            }
            return BaseLaser2DXMLReader::endElement(name);
        }

  private:
        bool _bProcessing;
    };
        
    class SpinningLaserGeomData : public LaserGeomData
    {
    public:
        dReal fSpinSpeed;
        Vector vSpinAxis, vSpinPos;
    };
    
public:
    static BaseXMLReaderPtr CreateXMLReader(InterfaceBasePtr ptr, const std::list<std::pair<std::string,std::string> >& atts)
    {
        return BaseXMLReaderPtr(new BaseSpinningLaser2DXMLReader(boost::dynamic_pointer_cast<BaseSpinningLaser2DSensor>(ptr)));
    }

 BaseSpinningLaser2DSensor(EnvironmentBasePtr penv) : BaseLaser2DSensor(penv) {
        __description = ":Interface Author: Rosen Diankov\nProvides a simulated spinning 2D laser range finder.";
        _fGeomSpinSpeed = 0;
        _vGeomSpinAxis = Vector(1,0,0);
        _fCurAngle = 0;
        _bSpinning = true;
    }
    
    virtual void Reset(int options)
    {
        BaseLaser2DSensor::Reset(options);
        _fCurAngle = 0;
        _bSpinning = true;
    }

    virtual bool SimulationStep(dReal fTimeElapsed)
    {
        if( _bSpinning ) {
            _fCurAngle += _fGeomSpinSpeed*fTimeElapsed;
            if( _fCurAngle > 2*PI )
                _fCurAngle -= 2*PI;
            if( fTimeToScan <= fTimeElapsed ) {
                // have to update
                SetTransform(_trans);
            }
        }

        return BaseLaser2DSensor::SimulationStep(fTimeElapsed);
    }

    virtual SensorGeometryPtr GetSensorGeometry()
    {
        SpinningLaserGeomData* pgeom = new SpinningLaserGeomData();
        *(LaserGeomData*)pgeom = *_pgeom;
        pgeom->fSpinSpeed = _fGeomSpinSpeed;
        pgeom->vSpinAxis = _vGeomSpinAxis;
        pgeom->vSpinPos = _vGeomSpinPos;
        return SensorGeometryPtr(pgeom);
    }

    virtual bool SendCommand(std::ostream& os, std::istream& is)
    {
        string cmd;
        streampos pos = is.tellg();
        is >> cmd;
        if( !is )
            throw openrave_exception("no command",ORE_InvalidArguments);
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        if( cmd == "spin" ) {
            is >> _bSpinning;
            SetTransform(_trans);
        }
        else {
            is.seekg(pos);
            return BaseLaser2DSensor::SendCommand(os,is);
        }

        return !!is;
    }

protected:
    virtual Transform GetLaserPlaneTransform()
    {
        Transform trot;
        trot.rotfromaxisangle(_vGeomSpinAxis, _fCurAngle);
        trot.trans = trot.rotate(-_vGeomSpinPos) + _vGeomSpinPos;
        return GetTransform() * trot;
    }

    dReal _fGeomSpinSpeed;
    Vector _vGeomSpinAxis;
    Vector _vGeomSpinPos;

    dReal _fCurAngle;
    bool _bSpinning;
};

#endif
