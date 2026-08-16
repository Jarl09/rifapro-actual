import { supabase } from './supabaseClient.mjs'

function ocultarTelefono(tel = '') {
  const limpio = tel.replace(/\D/g, '')
  if (limpio.length < 6) return limpio
  return `${limpio.slice(0, 3)}****${limpio.slice(-2)}`
}

function formatearFecha(fecha) {
  return new Date(fecha).toLocaleString('es-DO', {
    timeZone: 'America/Santo_Domingo',
    day: '2-digit',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  })
}

async function obtenerBoletos(compraId, configId) {
  const { data } = await supabase
    .from('boletos')
    .select('numero')
    .eq('compra_id', compraId)
    .eq('config_id', configId)

  return (data || []).map(b => b.numero)
}

function crearGrupo() {
  return {
    aprobadas: [],
    pendientes: [],
    rechazadas: []
  }
}

export async function buscarBoletos(valor) {
  const entrada = String(valor || '').replace(/\D/g, '')

  const { data: configActual, error: configError } = await supabase
    .from('configuracion')
    .select('id,titulo')
    .eq('estado', 'activa')
    .order('created_at', { ascending: false })
    .limit(1)
    .single()

  if (configError || !configActual) {
    return {
      estado: 'error',
      mensaje: 'No hay una rifa activa disponible'
    }
  }

  // BÚSQUEDA POR NÚMERO DE BOLETO
  if (entrada.length === 4) {
    const { data: boleto } = await supabase
      .from('boletos')
      .select('numero,compra_id')
      .eq('numero', entrada)
      .eq('config_id', configActual.id)
      .limit(1)
      .single()

    if (!boleto) {
      return { estado: 'no_encontrado' }
    }

    const { data: compra } = await supabase
      .from('compras')
      .select('id,nombre,telefono,estado,created_at')
      .eq('id', boleto.compra_id)
      .eq('config_id', configActual.id)
      .limit(1)
      .single()

    if (!compra) {
      return { estado: 'no_encontrado' }
    }

    const telefonoBusqueda = compra.telefono

    const { data: compras } = await supabase
      .from('compras')
      .select('id,nombre,telefono,estado,created_at')
      .ilike(
        'telefono',
        `%${telefonoBusqueda.replace(/\D/g, '')}%`
      )
      .eq('config_id', configActual.id)
      .order('created_at', { ascending: false })

    if (!compras || compras.length === 0) {
      return { estado: 'no_encontrado' }
    }

    const resultado = crearGrupo()

    for (const compraItem of compras) {
      const item = {
        fecha: formatearFecha(compraItem.created_at),
        boletos: [],
        estado: compraItem.estado
      }

      if (compraItem.estado === 'aprobado') {
        item.boletos = await obtenerBoletos(
          compraItem.id,
          configActual.id
        )
      }

      if (compraItem.estado === 'aprobado') {
        resultado.aprobadas.push(item)
      } else if (compraItem.estado === 'pendiente') {
        resultado.pendientes.push(item)
      } else if (compraItem.estado === 'rechazado') {
        resultado.rechazadas.push(item)
      }
    }

    return {
      estado: 'historial',
      nombre: compras[0].nombre,
      telefono: ocultarTelefono(compras[0].telefono),
      rifa: configActual.titulo,
      ...resultado
    }
  }

  // BÚSQUEDA POR TELÉFONO
  const { data: compras } = await supabase
    .from('compras')
    .select('id,nombre,telefono,estado,created_at')
    .eq('config_id', configActual.id)
    .ilike('telefono', `%${entrada}%`)
    .order('created_at', { ascending: false })

  if (!compras || compras.length === 0) {
    return {
      estado: 'no_encontrado'
    }
  }

  const resultado = crearGrupo()

  for (const compra of compras) {
    const item = {
      fecha: formatearFecha(compra.created_at),
      boletos: [],
      estado: compra.estado
    }

    if (compra.estado === 'aprobado') {
      item.boletos = await obtenerBoletos(
        compra.id,
        configActual.id
      )
    }

    if (compra.estado === 'aprobado') {
      resultado.aprobadas.push(item)
    } else if (compra.estado === 'pendiente') {
      resultado.pendientes.push(item)
    } else if (compra.estado === 'rechazado') {
      resultado.rechazadas.push(item)
    }
  }

  return {
    estado: 'historial',
    nombre: compras[0].nombre,
    telefono: ocultarTelefono(compras[0].telefono),
    rifa: configActual.titulo,
    ...resultado
  }
}