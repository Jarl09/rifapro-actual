import 'dotenv/config'
import express          from 'express'
import cors             from 'cors'
import multer           from 'multer'
import jwt              from 'jsonwebtoken'
import bcrypt           from 'bcrypt'

import { crearCompra }      from './compras.mjs'
import { aprobarCompra, rechazarCompra } from './admin.mjs'
import { buscarBoletos }    from './verificacion.mjs'
import { obtenerProgreso }  from './boletos.mjs'
import { subirComprobante } from './storage.mjs'
import { supabase }         from './supabaseClient.mjs'

// ─── VARIABLES DE ENTORNO ─────────────────────────────────────────────────────
const ENV_REQUIRED = ['JWT_SECRET']
for (const key of ENV_REQUIRED) {
  if (!process.env[key]) {
    console.error(`[FATAL] Variable de entorno faltante: ${key}`)
    process.exit(1)
  }
}

const JWT_SECRET  = process.env.JWT_SECRET
const PORT        = Number(process.env.PORT) || 3001
const CORS_ORIGIN = process.env.CORS_ORIGIN  || 'http://localhost:5173'

// ─── LOGGER ───────────────────────────────────────────────────────────────────
const log = {
  info:  (...a) => console.log( '[INFO] ',  new Date().toISOString(), ...a),
  warn:  (...a) => console.warn( '[WARN] ',  new Date().toISOString(), ...a),
  error: (...a) => console.error('[ERROR]', new Date().toISOString(), ...a),
}

// ─── CACHÉ EN MEMORIA ─────────────────────────────────────────────────────────
const cache = new Map()

function cacheGet(key) {
  const entry = cache.get(key)
  if (!entry) return null
  if (Date.now() > entry.expiresAt) { cache.delete(key); return null }
  return entry.value
}

function cacheSet(key, value, ttlMs) {
  cache.set(key, { value, expiresAt: Date.now() + ttlMs })
}

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const rateLimitMap = new Map()

function rateLimit({ windowMs = 60_000, max = 30 } = {}) {
  return (req, res, next) => {
    const ip  = req.ip || req.socket.remoteAddress || 'unknown'
    const key = `${ip}:${req.path}`
    const now = Date.now()
    let r = rateLimitMap.get(key)
    if (!r || now > r.resetAt) r = { count: 0, resetAt: now + windowMs }
    r.count++
    rateLimitMap.set(key, r)
    if (r.count > max) {
      log.warn('Rate limit', { ip, path: req.path })
      return sendError(res, 429, 'Demasiadas solicitudes. Intenta más tarde.')
    }
    next()
  }
}

setInterval(() => {
  const now = Date.now()
  for (const [k, v] of rateLimitMap) if (now > v.resetAt) rateLimitMap.delete(k)
}, 600_000)

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
})

// ─── MULTER ───────────────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 5 * 1024 * 1024 },
})

// ─── APP ──────────────────────────────────────────────────────────────────────
const app = express()

app.use(cors({
  origin: CORS_ORIGIN.split(',').map(v => v.trim()),
  methods: ['GET', 'POST', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}))

app.use(express.json({ limit: '50kb' }))
app.use(express.urlencoded({ extended: true }))


// ─── SANITIZACIÓN ─────────────────────────────────────────────────────────────
const sanitizeString  = (v, max = 200) => typeof v === 'string' ? v.trim().slice(0, max) : ''
const sanitizeEmail   = (v)            => sanitizeString(v, 254).toLowerCase()
const sanitizePhone   = (v)            => typeof v === 'string' ? v.replace(/\D/g, '').slice(0, 20) : ''
const sanitizeInt     = (v)            => { const n = parseInt(v, 10); return isNaN(n) || n <= 0 ? null : n }
const sanitizeNumber  = (v)            => { const n = Number(v);       return isNaN(n) || n <= 0 ? null : n }

// ─── ERROR UNIFORME ───────────────────────────────────────────────────────────
function sendError(res, status, message) {
  return res.status(status).json({ error: message })
}

// ─── AUDITORÍA ────────────────────────────────────────────────────────────────
async function registrarAuditoria({ usuario_id, usuario_email, accion, detalle = {} }) {
  try {
    await supabase.from('auditoria').insert([{ usuario_id, usuario_email, accion, detalle }])
  } catch (err) {
    log.error('auditoria insert falló', err.message)
  }
}

// ─── MIDDLEWARE JWT ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers['authorization']

  if (!header?.startsWith('Bearer ')) {
    return sendError(res, 401, 'Token requerido')
  }

  const token = header.slice(7).trim()

  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch (err) {
    return sendError(res, 401, 'Token inválido')
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.rol)) {
      log.warn('Acceso denegado por rol', {
        user: req.user?.email,
        required: roles
      })
      return sendError(res, 403, 'No tienes permiso para esta acción')
    }
    next()
  }
}

// ─── VALIDAR ARCHIVO ──────────────────────────────────────────────────────────
const MIME_OK = new Set(['image/jpeg', 'image/png', 'image/jpg', 'image/webp'])

function validarArchivo(file, res) {
  if (!file)                        return sendError(res, 400, 'Archivo requerido')
  if (!MIME_OK.has(file.mimetype))  return sendError(res, 400, 'Solo imágenes JPG, PNG o WEBP')
  if (file.size > 5 * 1024 * 1024) return sendError(res, 400, 'La imagen no puede superar 5 MB')
  return null
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RUTAS PÚBLICAS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/', (req, res) => res.json({ status: 'ok', version: '3.0' }))

 app.get('/config', async (req, res) => {
  try {
    const cached = cacheGet('config')
    if (cached) return res.json(cached)
    const { data, error } = await supabase
      .from('configuracion')
      .select('id, titulo, descripcion, precio, total_boletos, fecha_sorteo, estado, imagen_url, min_boletos')
      .order('created_at', { ascending: false })
      .limit(1).single()
    if (error) throw error
    cacheSet('config', data, 30_000)
    res.json(data)
  } catch (err) {
    log.error('/config', err.message)
    sendError(res, 500, 'No se pudo cargar la configuración')
  }
})


app.get('/progreso', async (req, res) => {
  try {
    const cached = cacheGet('progreso')
    if (cached) return res.json(cached)
    const progreso = await obtenerProgreso()
    cacheSet('progreso', progreso, 10_000)
    res.json(progreso)
  } catch (err) {
    log.error('/progreso', err.message)
    sendError(res, 500, 'Error obteniendo progreso')
  }
})

app.post('/verificar', async (req, res) => {

  console.log('BODY:', req.body)

  try {
    const valor = String(req.body?.valor || '').trim()

    console.log('VALOR:', valor)

    if (!valor || valor.length < 4) {
      return sendError(res, 400, 'Dato requerido')
    }

    const resultado = await buscarBoletos(valor)

    res.json(resultado)

  } catch (err) {

    console.log(err)

    sendError(res, 500, 'Error verificando boletos')

  }

})

app.post('/comprar',
  rateLimit({ windowMs: 60_000, max: 5 }),
  upload.single('file'),
  async (req, res) => {
    try {
      const fileError = validarArchivo(req.file, res)
      if (fileError) return fileError

      const nombre   = sanitizeString(req.body.nombre, 100)
      const telefono = sanitizePhone(req.body.telefono)
      const cantidad = sanitizeInt(req.body.cantidad)
      const monto    = sanitizeNumber(req.body.monto)
      const metodo   = sanitizeString(req.body.metodo_pago, 50)
      const acepta   = req.body.acepta === 'true'

      if (!nombre || nombre.length < 2) return sendError(res, 400, 'Nombre inválido')
      if (telefono.length < 7)          return sendError(res, 400, 'Teléfono inválido')
      if (!cantidad)                     return sendError(res, 400, 'Cantidad inválida')
      if (cantidad > 300) {
      return sendError(res, 400, 'Máximo 300 boletos por compra')
      }
      if (!monto)                        return sendError(res, 400, 'Monto inválido')
      if (!metodo)                       return sendError(res, 400, 'Método de pago requerido')
      if (!acepta)                       return sendError(res, 400, 'Debes aceptar las condiciones')

      const metodosValidos = new Set(['banreservas', 'popular', 'bhd', 'paypal'])
      if (!metodosValidos.has(metodo)) return sendError(res, 400, 'Método de pago no válido')

      let config = cacheGet('config')
      if (!config) {
        const { data, error } = await supabase
          .from('configuracion').select('*')
          .order('created_at', { ascending: false }).limit(1).single()
        if (error || !data) return sendError(res, 500, 'Configuración no disponible')
        config = data
        cacheSet('config', config, 30_000)
      }

      if (config.estado === 'finalizada') return sendError(res, 400, 'La rifa ya finalizó')
      if (config.estado === 'pausada')    return sendError(res, 400, 'La rifa está pausada')
      if (cantidad < (config.min_boletos || 1)) {
        return sendError(res, 400, `Mínimo ${config.min_boletos} boleto(s)`)
      }

      let totalEsperado =
       cantidad * config.precio

        if (metodo === 'paypal') {
          totalEsperado += 100
}
      if (monto !== totalEsperado) return sendError(res, 400, `Monto incorrecto. Debe ser RD$ ${totalEsperado}`)

        const {
        count:vendidos,
        error:ocupadosError
        }=await supabase
        .from('boletos')
        .select('*',{count:'exact',head:true})
        .eq('config_id',config.id)

        if(ocupadosError){
        throw ocupadosError
        }

      if (vendidos >= config.total_boletos) {
        return sendError(res, 400, 'No quedan boletos disponibles')
      }

      const restantes = config.total_boletos - vendidos

      if (cantidad > restantes) {
        return sendError(
          res,
          400,
          `Solo quedan ${restantes} boleto(s) disponibles`
        )
      }

      const hace10s = new Date(Date.now() - 10_000).toISOString()
      const { data: recientes } = await supabase
        .from('compras').select('id').eq('telefono', telefono).gte('created_at', hace10s).limit(1)
      if (recientes?.length > 0) return sendError(res, 429, 'Espera unos segundos antes de intentar de nuevo')

      const comprobante_url = await subirComprobante(req.file)
      if (!comprobante_url) return sendError(res, 500, 'Error subiendo el comprobante')

      
       const { data: configActual, error: configError } = await supabase
        .from('configuracion')
        .select('id')
        .eq('estado', 'activa')
        .order('created_at', { ascending: false })
        .limit(1)
        .single()

      if (configError || !configActual) {
        return sendError(res, 400, 'No hay una rifa activa disponible')
      }
        const compra = await crearCompra({
          nombre,
          telefono,
          cantidad,
          monto,
          comprobante_url,
          metodo_pago: metodo,
          estado: 'pendiente',
          config_id: configActual.id
        })

      cache.delete('progreso')
      log.info('/comprar OK', { nombre, cantidad, metodo })
      res.status(201).json(compra)

    } catch (err) {
      log.error('/comprar', err.message)
      sendError(res, 500, 'Error procesando la compra')
    }
  }
)

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTENTICACIÓN ADMIN
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/admin/login', loginRateLimit, async (req, res) => {
  const email = sanitizeEmail(req.body.email)
  const password = sanitizeString(req.body.password, 200).trim()
  const ERR = 'Credenciales incorrectas'

  if (!email || !password) return sendError(res, 400, ERR)

  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('id, email, password_hash, rol, activo')
      .eq('email', email)
      .limit(1)

    const usuario = data?.[0]

    if (error || !usuario) {
      await bcrypt.compare(password, '$2b$12$invalidhashtopreventtimingXXXXXXXXXXXXX')
      log.warn('/admin/login usuario no encontrado', { email, ip: req.ip })
      return sendError(res, 401, ERR)
    }

    if (!usuario.activo) {
      log.warn('/admin/login cuenta inactiva', { email, ip: req.ip })
      return sendError(res, 401, ERR)
    }

    const ok = await bcrypt.compare(password, usuario.password_hash)

    if (!ok) {
      log.warn('/admin/login contraseña incorrecta', { email, ip: req.ip })
      return sendError(res, 401, ERR)
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: '8h', issuer: 'rifapro' }
    )

    await registrarAuditoria({
      usuario_id: usuario.id,
      usuario_email: usuario.email,
      accion: 'login',
      detalle: { ip: req.ip },
    })

    log.info('/admin/login OK', { email, rol: usuario.rol })

    res.json({
      token,
      rol: usuario.rol,
      email: usuario.email,
      expiresIn: 28800,
    })

  } catch (err) {
    log.error('/admin/login', err.message)
    sendError(res, 500, 'Error en el servidor')
  }
})
// ═══════════════════════════════════════════════════════════════════════════════
//  RUTAS ADMIN (JWT requerido)
// ═══════════════════════════════════════════════════════════════════════════════

// ─── POST /admin/compradores — ambos roles ────────────────────────────────────
// Devuelve todas las compras (aprobadas + pendientes) con sus números de boleto
app.get('/admin/compradores', requireAuth, async (req, res) => {
  try {
    const { data: configActual, error: configError } = await supabase
      .from('configuracion')
      .select('id')
      .eq('estado', 'activa')
      .order('created_at', { ascending: false })
      .limit(1)
      .single()

    if (configError || !configActual) {
      return res.json([])
    }

    const { data, error } = await supabase
      .from('compras')
      .select(`
        id,
        nombre,
        telefono,
        cantidad,
        monto,
        metodo_pago,
        estado,
        created_at
      `)
      .eq('config_id', configActual.id)
      .in('estado', ['aprobado', 'pendiente', 'rechazado'])
      .order('created_at', { ascending: true })

    if (error) throw error

    const ids = data
      .filter(c => c.estado === 'aprobado')
      .map(c => c.id)

let boletosMap = {}

if (ids.length) {

  const { data: boletos, error: bErr } = await supabase
    .from('boletos')
    .select('compra_id, numero')
    .in('compra_id', ids)
    .order('numero', { ascending: true })

  if (!bErr && boletos) {

    boletos.forEach(b => {

      if (!boletosMap[b.compra_id]) {
        boletosMap[b.compra_id] = []
      }

      boletosMap[b.compra_id].push(b.numero)

    })
  }
}

    const resultado = data.map(c => ({
      ...c,
      boletos: boletosMap[c.id] || [],
    }))

    res.json(resultado)

  } catch (err) {
    log.error('/admin/compradores', err.message)
    sendError(res, 500, 'Error cargando compradores')
  }
})

app.get('/admin/pendientes', requireAuth, async (req, res) => {
  try {
    const { data: configActual, error: configError } = await supabase
      .from('configuracion')
      .select('id')
      .eq('estado', 'activa')
      .order('created_at', { ascending: false })
      .limit(1)
      .single()

    if (configError || !configActual) {
      return res.json([])
    }

    // Limpiar compras atascadas en "procesando" por más de 5 minutos
    const hace5Min = new Date(Date.now() - 5 * 60 * 1000).toISOString()

    await supabase
      .from('compras')
      .update({ estado: 'pendiente' })
      .eq('config_id', configActual.id)
      .eq('estado', 'procesando')
      .lt('updated_at', hace5Min)

    const { data, error } = await supabase
      .from('compras')
      .select(`
        id,
        nombre,
        telefono,
        cantidad,
        monto,
        comprobante_url,
        metodo_pago,
        created_at,
        estado
      `)
      .eq('config_id', configActual.id)
      .eq('estado', 'pendiente')
      .order('created_at', { ascending: true })

    if (error) throw error

    res.json(data)

  } catch (err) {
    log.error('/admin/pendientes', err.message)
    sendError(res, 500, 'Error cargando pendientes')
  }
})


app.post('/admin/compras/:id/aprobar', requireAuth, async (req, res) => {
  try {
    const compra_id = sanitizeString(req.params.id, 100)
    if (!compra_id) return sendError(res, 400, 'compra_id requerido')

    const boletos = await aprobarCompra(compra_id)
    cache.delete('progreso')

    await registrarAuditoria({
      usuario_id: req.user.id,
      usuario_email: req.user.email,
      accion: 'aprobar_compra',
      detalle: { compra_id, boletos },
    })

    log.info('/admin/compras/aprobar', { compra_id, por: req.user.email })
    res.json({ boletos })

  } catch (err) {
    log.error('/admin/compras/aprobar', err.message)
    sendError(res, 500, 'Error aprobando compra')
  }
})

app.post('/admin/compras/:id/rechazar', requireAuth, async (req, res) => {
  try {
    const compra_id = sanitizeString(req.params.id, 100)
    if (!compra_id) return sendError(res, 400, 'compra_id requerido')

    await rechazarCompra(compra_id)
    cache.delete('progreso')

    await registrarAuditoria({
      usuario_id: req.user.id,
      usuario_email: req.user.email,
      accion: 'rechazar_compra',
      detalle: { compra_id },
    })

    log.info('/admin/compras/rechazar', { compra_id, por: req.user.email })
    res.json({ ok: true })

  } catch (err) {
    log.error('/admin/compras/rechazar', err.message)
    sendError(res, 500, 'Error rechazando compra')
  }
})
// Configuración — solo superadmin
app.post(
  '/admin/config',
  requireAuth, requireRole('superadmin'),
  upload.single('imagen'),
  async (req, res) => {
    try {
      const titulo      = sanitizeString(req.body.titulo, 200)
      const descripcion = sanitizeString(req.body.descripcion, 1000)
      const precio      = sanitizeNumber(req.body.precio)
      const total       = sanitizeInt(req.body.total)
      const minBoletos  = sanitizeInt(req.body.min_boletos) || 1
      const estado      = 'activa'

      if (!titulo) return sendError(res, 400, 'Título requerido')
      if (!descripcion) return sendError(res, 400, 'Descripción requerida')
      if (!precio || precio <= 0) return sendError(res, 400, 'Precio inválido')
      if (!total || total < 10) return sendError(res, 400, 'Total de boletos inválido')
      if (!minBoletos || minBoletos < 1 || minBoletos > total) {
        return sendError(res, 400, 'Compra mínima inválida')
      }
      if (!req.file) return sendError(res, 400, 'Imagen requerida')

      const fileError = validarArchivo(req.file, res)
      if (fileError) return fileError

      const ext  = req.file.mimetype === 'image/png' ? 'png' : 'jpg'
      const path = `rifa_${Date.now()}.${ext}`

      const { error: uploadError } = await supabase.storage
        .from('comprobantes')
        .upload(path, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        })

      if (uploadError) throw uploadError
        const imagen_url = supabase.storage
          .from('comprobantes')
          .getPublicUrl(path).data.publicUrl

        const hace10s = new Date(Date.now() - 10_000).toISOString()

        const { data: reciente, error: dupError } = await supabase
          .from('configuracion')
          .select('id')
          .eq('titulo', titulo)
          .eq('precio', precio)
          .gte('created_at', hace10s)
          .limit(1)

        if (dupError) throw dupError
        if (reciente?.length) {
          return sendError(res, 409, 'Ya existe una rifa similar creada hace unos segundos')
        }

        const payload = {
        titulo,
        descripcion,
        precio,
        total_boletos: total,
        min_boletos: minBoletos,
        estado,
        imagen_url
      }

      const { data: nueva, error } = await supabase
        .from('configuracion')
        .insert([payload])
        .select('id')
        .single()

      if (error) throw error

      cache.delete('config')
      cache.delete('progreso')

      log.info('/admin/config creada', { titulo, por: req.user.email })
      res.json({ ok: true, id: nueva.id })

    } catch (err) {
      log.error('/admin/config POST', err.message)
      sendError(res, 500, 'Error guardando configuración')
    }
  }
)

app.patch(
  '/admin/config/:id',
  requireAuth, requireRole('superadmin'),
  upload.single('imagen'),
  async (req, res) => {
    try {
      const id          = sanitizeString(req.params.id, 100)
      const titulo      = sanitizeString(req.body.titulo, 200) || null
      const descripcion = sanitizeString(req.body.descripcion, 1000) || null
      const fecha       = sanitizeString(req.body.fecha_sorteo, 50) || null
      const precio      = sanitizeNumber(req.body.precio) || null
      const totalBoletos = sanitizeInt(req.body.total_boletos) || null
      const tieneMinBoletos = req.body.min_boletos !== undefined

                if (
          !titulo &&
          !descripcion &&
          !fecha &&
          !precio &&
          !totalBoletos &&
          !tieneMinBoletos &&
          !req.file
        ) {
          return sendError(res, 400, 'Nada que actualizar')
        }
                    const cambios = {}

              if (titulo) cambios.titulo = titulo

              if (descripcion) {
                cambios.descripcion = descripcion
              }

              if (fecha) {
                cambios.fecha_sorteo = fecha
              }

              if (precio && precio > 0) {
                cambios.precio = precio
              }

              if (totalBoletos) {

                if (totalBoletos > 10000) {
                  return sendError(
                    res,
                    400,
                    'Máximo 10000 boletos'
                  )
                }

                const { count, error: countError } = await supabase
                  .from('boletos')
                  .select('*', {
                    count: 'exact',
                    head: true
                  })
                  .eq('config_id', id)

                if (countError) throw countError

                const vendidos = count || 0

                if (totalBoletos < vendidos) {
                  return sendError(
                    res,
                    400,
                    `Ya existen ${vendidos} boletos vendidos`
                  )
                }

                cambios.total_boletos = totalBoletos
              }
             if (tieneMinBoletos) {
  const minBoletos = sanitizeInt(req.body.min_boletos)

  if (!minBoletos || minBoletos < 1) {
    return sendError(
      res,
      400,
      'La cantidad mínima debe ser al menos 1 boleto'
    )
  }

  // Usar el total nuevo si se está modificando,
  // o el total actual de la rifa si no se modifica.
  const { data: configActual, error: configError } = await supabase
    .from('configuracion')
    .select('total_boletos')
    .eq('id', id)
    .single()

  if (configError || !configActual) {
    return sendError(res, 404, 'Rifa no encontrada')
  }

  const totalFinal = totalBoletos || configActual.total_boletos

  const { count: vendidos, error: countError } = await supabase
    .from('boletos')
    .select('*', {
      count: 'exact',
      head: true
    })
    .eq('config_id', id)

  if (countError) throw countError

  const disponibles = totalFinal - (vendidos || 0)

  if (minBoletos > disponibles) {
    return sendError(
      res,
      400,
      `La cantidad mínima no puede superar los ${disponibles} boletos disponibles`
    )
  }

  cambios.min_boletos = minBoletos
}
      if (req.file) {
      const fileError = validarArchivo(req.file, res)
      if (fileError) return fileError

      const ext = req.file.mimetype === 'image/png' ? 'png' : 'jpg'
      const path = `rifa_${Date.now()}.${ext}`

      const { error: uploadError } = await supabase.storage
        .from('comprobantes')
        .upload(path, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        })

      if (uploadError) throw uploadError

      cambios.imagen_url = supabase.storage
        .from('comprobantes')
        .getPublicUrl(path).data.publicUrl
    }
      const { error } = await supabase
        .from('configuracion')
        .update(cambios)
        .eq('id', id)

      if (error) throw error

      cache.delete('config')
      cache.delete('progreso')

      log.info('/admin/config PATCH', {
        id,
        campos: Object.keys(cambios),
        por: req.user.email
      })

      res.json({ ok: true })

    } catch (err) {
      log.error('/admin/config PATCH', err.message)
      sendError(res, 500, 'Error actualizando configuración')
    }
  }
)
// Auditoría — solo superadmin
app.get('/admin/auditoria', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const limit = Math.min(sanitizeInt(req.query.limit) || 50, 200)
    const { data, error } = await supabase
      .from('auditoria')
      .select('id, usuario_email, accion, detalle, created_at')
      .order('created_at', { ascending: false })
      .limit(limit)
    if (error) throw error
    res.json(data)
  } catch (err) {
    log.error('/admin/auditoria', err.message)
    sendError(res, 500, 'Error cargando auditoría')
  }
})

// ═══════════════════════════════════════════════════════════════════════════════
//  GESTIÓN DE USUARIOS — solo superadmin
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/admin/usuarios', requireAuth, requireRole('superadmin'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('id, email, rol, activo, created_at')
      .order('created_at', { ascending: false })
    if (error) throw error
    res.json(data)
  } catch (err) {
    log.error('/admin/usuarios GET', err.message)
    sendError(res, 500, 'Error cargando usuarios')
  }
})

app.post(
  '/admin/usuarios',
  requireAuth, requireRole('superadmin'),
  rateLimit({ windowMs: 60_000, max: 10 }),
  async (req, res) => {
    try {
     const email = sanitizeEmail(req.body.email)

    const password = sanitizeString(req.body.password, 200)
      .trim()

    const rol = sanitizeString(req.body.rol, 20)

      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendError(res, 400, 'Email inválido')
      if (!password || password.length < 8) return sendError(res, 400, 'La contraseña debe tener al menos 8 caracteres')
      if (!new Set(['superadmin', 'encargado']).has(rol)) return sendError(res, 400, 'Rol inválido')

      const { data: existe, error: existeError } = await supabase
    .from('usuarios')
    .select('id')
    .eq('email', email)
    .limit(1)

    if (existeError) throw existeError
    if (existe?.length) return sendError(res, 409, 'Ya existe un usuario con ese email')
      const password_hash = await bcrypt.hash(password, 12)

      const { data: nuevo, error } = await supabase
        .from('usuarios')
        .insert([{ email, password_hash, rol, activo: true }])
        .select('id, email, rol, activo, created_at')
        .single()

      if (error) throw error

      await registrarAuditoria({
        usuario_id: req.user.id, usuario_email: req.user.email,
        accion: 'crear_usuario', detalle: { nuevo_email: email, rol },
      })

      log.info('/admin/usuarios creado', { email, rol, por: req.user.email })
      res.status(201).json(nuevo)

    } catch (err) {
      log.error('/admin/usuarios POST', err.message)
      sendError(res, 500, 'Error creando usuario')
    }
  }
)

app.patch(
  '/admin/usuarios/:id',
  requireAuth, requireRole('superadmin'),
  async (req, res) => {
    try {
      const id     = sanitizeString(req.params.id, 100)
      const activo = req.body.activo === true || req.body.activo === 'true'

      if (id === req.user.id) return sendError(res, 400, 'No puedes modificar tu propia cuenta')

      const { error } = await supabase.from('usuarios').update({ activo }).eq('id', id)
      if (error) throw error

      await registrarAuditoria({
        usuario_id: req.user.id, usuario_email: req.user.email,
        accion: activo ? 'activar_usuario' : 'desactivar_usuario',
        detalle: { usuario_id: id },
      })

      log.info('/admin/usuarios PATCH', { id, activo, por: req.user.email })
      res.json({ ok: true })

    } catch (err) {
      log.error('/admin/usuarios PATCH', err.message)
      sendError(res, 500, 'Error actualizando usuario')
    }
  }
)

// ─── 404 y error global ───────────────────────────────────────────────────────
app.use((req, res) => sendError(res, 404, 'Ruta no encontrada'))
app.use((err, req, res, _next) => {
  log.error('Error no controlado', err.message)
  sendError(res, 500, 'Error interno del servidor')
})

app.listen(PORT, () => log.info(`Servidor listo en http://localhost:${PORT}`))